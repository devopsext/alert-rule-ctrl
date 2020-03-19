package cmd

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/coreos/prometheus-operator/pkg/listwatch"

	"github.com/ghodss/yaml"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/openshift/prom-label-proxy/injectproxy"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

//This file holds functions ported from github.com/coreos/prometheus-operator/pkg/prometheus/rules.go

const (
	resyncPeriod = 5 * time.Minute
)

// The maximum `Data` size of a ConfigMap seems to differ between
// environments. This is probably due to different meta data sizes which count
// into the overall maximum size of a ConfigMap. Thereby lets leave a
// large buffer.
var maxConfigMapDataSize = int(float64(v1.MaxSecretSize) * 0.5)

type ruleController struct {
	kclient                kubernetes.Interface
	mclient                monitoringclient.Interface
	allowedRulesNamespaces []string
	namespace              string
	ruleInf                cache.SharedIndexInformer
	ruleSelector           *metav1.LabelSelector
	configmapSelector      []string
	configMapNamePrefix    string
	logger                 log.Logger
}

func (rc *ruleController) handleRuleAdd(obj interface{}) {

	level.Info(rc.logger).Log("msg", "PrometheusRule added",
		"ns", obj.(*monitoringv1.PrometheusRule).Namespace,
		"rule", obj.(*monitoringv1.PrometheusRule).Name)

	ruleConfigMapNames, err := rc.createOrUpdateRuleConfigMaps()
	if err != nil {
		level.Error(rc.logger).Log("msg", "Can't create/update config map",
			"err", err.Error())
	} else {
		for _, ruleCm := range ruleConfigMapNames {
			level.Debug(rc.logger).Log("msg", "Config map created/updated",
				"config map", ruleCm)
		}
	}

}

func (rc *ruleController) handleRuleUpdate(old, cur interface{}) {
	if old.(*monitoringv1.PrometheusRule).ResourceVersion == cur.(*monitoringv1.PrometheusRule).ResourceVersion {
		return
	}

	level.Info(rc.logger).Log("msg", "PrometheusRule updated",
		"ns", cur.(*monitoringv1.PrometheusRule).Namespace,
		"rule", cur.(*monitoringv1.PrometheusRule).Name)

	ruleConfigMapNames, err := rc.createOrUpdateRuleConfigMaps()
	if err != nil {
		level.Error(rc.logger).Log("msg", "Can't create/update config map",
			"err", err.Error())
	} else {
		for _, ruleCm := range ruleConfigMapNames {
			level.Debug(rc.logger).Log("msg", "Config map created/updated",
				"config map", ruleCm)
		}
	}
}

func (rc *ruleController) handleRuleDelete(obj interface{}) {

	level.Info(rc.logger).Log("msg", "PrometheusRule deleted",
		"ns", obj.(*monitoringv1.PrometheusRule).Namespace,
		"rule", obj.(*monitoringv1.PrometheusRule).Name)

	ruleConfigMapNames, err := rc.createOrUpdateRuleConfigMaps()
	if err != nil {
		level.Error(rc.logger).Log("msg", "Can't create/update config map",
			"err", err.Error())
	} else {
		for _, ruleCm := range ruleConfigMapNames {
			level.Debug(rc.logger).Log("msg", "Config map created/updated",
				"config map", ruleCm)
		}
	}
}

func NewRuleController(logger log.Logger,
	cfg *rest.Config,
	allowNamespaceList []string, denyNamespaceList []string,
	cmNamespace string, cmNamePrefix string, cmLabels []string,
	ruleLabels []string) (*ruleController, error) {

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Errorf("instantiating kubernetes client failed: %s", err.Error())
	}

	mclient, err := monitoringclient.NewForConfig(cfg)

	if err != nil {
		return nil, errors.Errorf("instantiating monitoring client failed: %s", err.Error())
	}

	ruleInf := cache.NewSharedIndexInformer(
		listwatch.MultiNamespaceListerWatcher(logger, allowNamespaceList, denyNamespaceList, func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return mclient.MonitoringV1().PrometheusRules(namespace).List(options)
				},
				WatchFunc: mclient.MonitoringV1().PrometheusRules(namespace).Watch,
			}
		}),
		&monitoringv1.PrometheusRule{}, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	ruleMatchLabels := map[string]string{}
	for _, keyValue := range ruleLabels {
		splitted := strings.Split(keyValue, "=")
		if len(splitted) > 1 {
			ruleMatchLabels[splitted[0]] = splitted[1]
		}

	}

	rc := &ruleController{
		kclient:                client,
		mclient:                mclient,
		ruleInf:                ruleInf,
		allowedRulesNamespaces: allowNamespaceList,
		namespace:              cmNamespace,
		ruleSelector:           &metav1.LabelSelector{MatchLabels: ruleMatchLabels},
		configmapSelector:      cmLabels,
		configMapNamePrefix:    cmNamePrefix,
		logger:                 logger,
	}

	ruleInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    rc.handleRuleAdd,
		DeleteFunc: rc.handleRuleDelete,
		UpdateFunc: rc.handleRuleUpdate,
	})

	return rc, nil
}

func (rc *ruleController) createOrUpdateRuleConfigMaps() ([]string, error) {
	cClient := rc.kclient.CoreV1().ConfigMaps(rc.namespace)

	newRules, err := rc.selectRules(rc.allowedRulesNamespaces)
	if err != nil {
		return nil, err
	}

	currentConfigMapList, err := cClient.List(metav1.ListOptions{LabelSelector: strings.Join(rc.configmapSelector, ",")})
	if err != nil {
		return nil, err
	}
	currentConfigMaps := currentConfigMapList.Items

	currentRules := map[string]string{}
	for _, cm := range currentConfigMaps {
		for ruleFileName, ruleFile := range cm.Data {
			currentRules[ruleFileName] = ruleFile
		}
	}

	equal := reflect.DeepEqual(newRules, currentRules)
	if equal && len(currentConfigMaps) != 0 {
		level.Debug(rc.logger).Log(
			"msg", "no PrometheusRule changes",
			"namespace", strings.Join(rc.allowedRulesNamespaces, ","))

		currentConfigMapNames := []string{}
		for _, cm := range currentConfigMaps {
			currentConfigMapNames = append(currentConfigMapNames, cm.Name)
		}
		return currentConfigMapNames, nil
	}

	newConfigMaps, err := rc.makeRulesConfigMaps(newRules)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make rules ConfigMaps")
	}

	newConfigMapNames := []string{}
	for _, cm := range newConfigMaps {
		newConfigMapNames = append(newConfigMapNames, cm.Name)
	}

	if len(currentConfigMaps) == 0 {
		level.Debug(rc.logger).Log(
			"msg", "no PrometheusRule configmap found, creating new one",
			"namespace", rc.namespace,
		)
		for _, cm := range newConfigMaps {
			_, err = cClient.Create(&cm)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create ConfigMap '%v'", cm.Name)
			}
		}
		return newConfigMapNames, nil
	}

	// Simply deleting old ConfigMaps and creating new ones for now. Could be
	// replaced by logic that only deletes obsolete ConfigMaps in the future.
	for _, cm := range currentConfigMaps {
		err := cClient.Delete(cm.Name, &metav1.DeleteOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to delete current ConfigMap '%v'", cm.Name)
		}
	}

	level.Debug(rc.logger).Log(
		"msg", "updating Config maps",
		"namespace", rc.namespace,
	)
	for _, cm := range newConfigMaps {
		_, err = cClient.Create(&cm)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create new ConfigMap '%v'", cm.Name)
		}
	}

	return newConfigMapNames, nil
}

func (rc *ruleController) selectRules(namespaces []string) (map[string]string, error) {
	rules := map[string]string{}

	ruleSelector, err := metav1.LabelSelectorAsSelector(rc.ruleSelector)
	if err != nil {
		return rules, errors.Wrap(err, "convert rule label selector to selector")
	}

	for _, ns := range namespaces {
		var marshalErr error
		err := cache.ListAllByNamespace(rc.ruleInf.GetIndexer(), ns, ruleSelector, func(obj interface{}) {
			promRule := obj.(*monitoringv1.PrometheusRule)
			content, err := generateContent(promRule.Spec, "", promRule.Namespace)
			if err != nil {
				marshalErr = err
				return
			}
			rules[fmt.Sprintf("%v-%v.yaml", promRule.Namespace, promRule.Name)] = content
		})
		if err != nil {
			return nil, err
		}
		if marshalErr != nil {
			return nil, marshalErr
		}
	}

	ruleNames := []string{}
	for name := range rules {
		ruleNames = append(ruleNames, name)
	}

	level.Debug(rc.logger).Log(
		"msg", "selected Rules",
		"rules", strings.Join(ruleNames, ","),
		"namespace", strings.Join(namespaces, ","))

	return rules, nil
}

func generateContent(promRule monitoringv1.PrometheusRuleSpec, enforcedNsLabel, ns string) (string, error) {
	if enforcedNsLabel != "" {
		for gi, group := range promRule.Groups {
			group.PartialResponseStrategy = ""
			for ri, r := range group.Rules {
				if len(promRule.Groups[gi].Rules[ri].Labels) == 0 {
					promRule.Groups[gi].Rules[ri].Labels = map[string]string{}
				}
				promRule.Groups[gi].Rules[ri].Labels[enforcedNsLabel] = ns

				expr := r.Expr.String()
				parsedExpr, err := promql.ParseExpr(expr)
				if err != nil {
					return "", errors.Wrap(err, "failed to parse promql expression")
				}
				err = injectproxy.SetRecursive(parsedExpr, []*labels.Matcher{{
					Name:  enforcedNsLabel,
					Type:  labels.MatchEqual,
					Value: ns,
				}})
				if err != nil {
					return "", errors.Wrap(err, "failed to inject labels to expression")
				}

				promRule.Groups[gi].Rules[ri].Expr = intstr.FromString(parsedExpr.String())
			}
		}
	}
	content, err := yaml.Marshal(promRule)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmarshal content")
	}
	return string(content), nil
}

// makeRulesConfigMaps takes a Prometheus configuration and rule files and
// returns a list of Kubernetes ConfigMaps to be later on mounted into the
// Prometheus instance.
// If the total size of rule files exceeds the Kubernetes ConfigMap limit,
// they are split up via the simple first-fit [1] bin packing algorithm. In the
// future this can be replaced by a more sophisticated algorithm, but for now
// simplicity should be sufficient.
// [1] https://en.wikipedia.org/wiki/Bin_packing_problem#First-fit_algorithm
func (rc *ruleController) makeRulesConfigMaps(ruleFiles map[string]string) ([]v1.ConfigMap, error) {
	//check if none of the rule files is too large for a single ConfigMap
	for filename, file := range ruleFiles {
		if len(file) > maxConfigMapDataSize {
			return nil, errors.Errorf(
				"rule file '%v' is too large for a single Kubernetes ConfigMap",
				filename,
			)
		}
	}

	buckets := []map[string]string{
		{},
	}
	currBucketIndex := 0

	// To make bin packing algorithm deterministic, sort ruleFiles filenames and
	// iterate over filenames instead of ruleFiles map (not deterministic).
	fileNames := []string{}
	for n := range ruleFiles {
		fileNames = append(fileNames, n)
	}
	sort.Strings(fileNames)

	for _, filename := range fileNames {
		// If rule file doesn't fit into current bucket, create new bucket.
		if bucketSize(buckets[currBucketIndex])+len(ruleFiles[filename]) > maxConfigMapDataSize {
			buckets = append(buckets, map[string]string{})
			currBucketIndex++
		}
		buckets[currBucketIndex][filename] = ruleFiles[filename]
	}

	ruleFileConfigMaps := []v1.ConfigMap{}
	for i, bucket := range buckets {
		cm := rc.makeRulesConfigMap(bucket)
		cm.Name = cm.Name + "-" + strconv.Itoa(i)
		ruleFileConfigMaps = append(ruleFileConfigMaps, cm)
	}

	return ruleFileConfigMaps, nil
}

func bucketSize(bucket map[string]string) int {
	totalSize := 0
	for _, v := range bucket {
		totalSize += len(v)
	}

	return totalSize
}

func (rc *ruleController) makeRulesConfigMap(ruleFiles map[string]string) v1.ConfigMap {

	labels := map[string]string{}
	for _, keyValue := range rc.configmapSelector {
		splitted := strings.Split(keyValue, "=")
		if len(splitted) > 1 {
			labels[splitted[0]] = splitted[1]
		}

	}

	return v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:   rc.configMapNamePrefix + "-rulefiles",
			Labels: labels,
		},
		Data: ruleFiles,
	}
}

func (rc *ruleController) waitForCacheSync(stopc <-chan struct{}) error {
	ok := true
	informers := []struct {
		name     string
		informer cache.SharedIndexInformer
	}{
		{"PrometheusRule", rc.ruleInf},
	}
	for _, inf := range informers {
		if !cache.WaitForCacheSync(stopc, inf.informer.HasSynced) {
			level.Error(rc.logger).Log("msg", fmt.Sprintf("failed to sync %s cache", inf.name))
			ok = false
		} else {
			level.Debug(rc.logger).Log("msg", fmt.Sprintf("successfully synced %s cache", inf.name))
		}
	}
	if !ok {
		return errors.New("failed to sync caches")
	}
	level.Info(rc.logger).Log("msg", "successfully synced all caches")
	return nil
}
