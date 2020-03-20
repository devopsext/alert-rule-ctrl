package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/coreos/prometheus-operator/pkg/k8sutil"
	"github.com/devopsext/alert-rule-ctrl/version"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

//Globals
var (
	logger              log.Logger
	selfName            string
	cmdRoot, cmdVersion *cobra.Command
)

// Variables used in flags.
var (
	logLevel               string
	k8sAPIEndpoint         string
	caData, caFile         string
	certData, certFile     string
	keyData, keyFile       string
	tlsInsecure            bool
	allowedRulesNamespaces []string
	deniedRulesNamespaces  []string
	cfgMapNamespace        string
	cfgMapNamePrefix       string
	cmLabels               []string
	rulesLabelsSelector    []string
)

func cmdRootOnInit() {
	//Initialize logger
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	switch logLevel {
	case "DEBUG":
		logger = level.NewFilter(logger, level.AllowDebug())
	case "INFO":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "WARN":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "ERROR":
		logger = level.NewFilter(logger, level.AllowError())
	default:
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	level.Debug(logger).Log("msg", "Started with cmdline: "+strings.Join(os.Args, " "))
}

func Execute() int {
	if err := cmdRoot.Execute(); err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

func init() {
	selfName = filepath.Base(os.Args[0])
	cmdRoot = &cobra.Command{
		Use:   selfName + " [parameters]",
		Short: selfName + " is a simple controller for PrometheusRule CRDs",
		Long: selfName + ` is a tool that monitor PrometheusRule CRDs 
and maintain config map with rule contents. This tool is a subset of coreos prometheus operator (https://github.com/coreos/prometheus-operator)`,
		Run: cmdRootRun,
	}

	cmdVersion = &cobra.Command{
		Use:     "version",
		Short:   "Print version information",
		Aliases: []string{"v"},
		Run: func(cmd *cobra.Command, args []string) {

			var parts = []string{selfName + ":"}

			if version.Version != "" {
				parts = append(parts, version.Version)
			} else {
				parts = append(parts, "unknown")
			}

			if version.Commit != "" {
				parts = append(parts, "commit:", version.Commit)
			}

			fmt.Println(strings.Join(parts, " "))
		},
	}

	cobra.OnInitialize(cmdRootOnInit)
	cmdRoot.AddCommand(cmdVersion)
	cmdRoot.PersistentFlags().StringVarP(
		&logLevel,
		"logLevel",
		"l",
		"INFO",
		"Logging level,valid values: DEBUG,INFO,WARN,ERROR")

	cmdRoot.PersistentFlags().StringVarP(
		&k8sAPIEndpoint,
		"apiEndpoint",
		"",
		"",
		`K8S API Endpoint to connect to, if not specified, 
then assumed that running inside k8s (Ignored if 'KUBECONFIG' env. var is set).
Example: https://localhost:6443`)

	cmdRoot.PersistentFlags().StringVarP(
		&caData,
		"caData",
		"",
		"",
		"K8S CA data in a plain text (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)")

	cmdRoot.PersistentFlags().StringVarP(
		&caFile,
		"caFile",
		"",
		"",
		"Path to k8s CA file (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)")

	cmdRoot.PersistentFlags().StringVarP(
		&certData,
		"certData",
		"",
		"",
		"K8S cert data in a plain text for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)")

	cmdRoot.PersistentFlags().StringVarP(
		&certFile,
		"certFile",
		"",
		"",
		"Path to k8s cert file for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)")

	cmdRoot.PersistentFlags().StringVarP(
		&keyData,
		"keyData",
		"",
		"",
		"K8S key data in a plain text for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)")

	cmdRoot.PersistentFlags().StringVarP(
		&keyFile,
		"keyFile",
		"",
		"",
		"Path to k8s key file for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)")

	cmdRoot.PersistentFlags().BoolVarP(
		&tlsInsecure,
		"tlsInsecure",
		"",
		false,
		"Don't verify API server's CA certificate.")

	cmdRoot.PersistentFlags().StringArrayVarP(
		&allowedRulesNamespaces,
		"allowedNamespace",
		"",
		[]string{},
		`Allowed namespace (multiple values accepted), where rules CRDs would be tracked.
This is mutually exclusive with --deniedNamespace.
(make sure you start under account with sufficient rights)`)

	cmdRoot.PersistentFlags().StringArrayVarP(
		&deniedRulesNamespaces,
		"deniedNamespace",
		"",
		[]string{},
		`Denied namespace (multiple values accepted), where rules CRDs would NOT be tracked 
This is mutually exclusive with --allowedNamespace.
(make sure you start under account with sufficient rights)`)

	cmdRoot.PersistentFlags().StringVarP(
		&cfgMapNamespace,
		"cmNamespace",
		"",
		"",
		"Namespace to hold config map with alert rules")

	cmdRoot.PersistentFlags().StringVarP(
		&cfgMapNamePrefix,
		"cmNamePrefix",
		"",
		"poarctrl",
		"Config map name prefix, that will store alert rules")

	cmdRoot.PersistentFlags().StringArrayVarP(
		&cmLabels,
		"cmLabels",
		"",
		[]string{},
		"Labels to add to rules config map (multiple values accepted). Format 'key=value'")

	cmdRoot.PersistentFlags().StringArrayVarP(
		&rulesLabelsSelector,
		"ruleLabelsSelector",
		"",
		[]string{},
		"Rule labels, to select rules (multiple values accepted). Format 'key=value'")

}

func cmdRootRun(cmd *cobra.Command, args []string) {

	level.Info(logger).Log("msg", "Version: "+version.Version)

	tlsConfig := rest.TLSClientConfig{
		CAData:   []byte(caData),
		CAFile:   caFile,
		CertData: []byte(certData),
		CertFile: certFile,
		KeyData:  []byte(keyData),
		KeyFile:  keyFile}

	cfg, err := k8sutil.NewClusterConfig(k8sAPIEndpoint, tlsInsecure, &tlsConfig)
	if err != nil {
		level.Error(logger).Log("msg", "instantiating cluster config failed", "err", err.Error())
		return
	}

	if len(allowedRulesNamespaces) == 0 {
		allowedRulesNamespaces = append(allowedRulesNamespaces, v1.NamespaceAll)
	}

	if len(allowedRulesNamespaces) != 0 && len(deniedRulesNamespaces) != 0 {
		level.Error(logger).Log("msg", "'--allowedNamespace' and '--deniedNamespace' parameters are mutually exclusive")
	}

	if cfgMapNamespace == "" {
		cfgMapNamespace = "default"
		level.Warn(logger).Log("msg", "config map namespace not specified and set to "+cfgMapNamespace)
	}

	rc, err := NewRuleController(logger,
		cfg,
		allowedRulesNamespaces, deniedRulesNamespaces,
		cfgMapNamespace,
		cfgMapNamePrefix,
		cmLabels,
		rulesLabelsSelector)
	if err != nil {
		level.Error(logger).Log("msg", "failed to create rule controller", "err", err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		stopc := ctx.Done()
		go rc.ruleInf.Run(stopc)
		if err := rc.waitForCacheSync(stopc); err != nil {
			return err
		}
		<-stopc
		return nil
	})

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		level.Info(logger).Log("msg", "Received SIGTERM, exiting gracefully...")
	case <-ctx.Done():
	}
	cancel()
}
