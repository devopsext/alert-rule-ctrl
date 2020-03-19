# alert-rule-ctrl
Subset of coreos prometheus operator (https://github.com/coreos/prometheus-operator) to handle PrometheusRule CRD (alerting rules).

### Motivation: 
Prometheus operator looks rather heavy solution and still can't (maybe never) adopt already existing prometheus installation (suppose you have your own prometheus installation and you don't want prometheus operator to rule it).
In order to bring prometheus alert rules feature in a form of CRD 'PrometheusRule' this tiny service was created.

This allow to keep the minimal footprint - one sidecar container in prometheus POD (this service + configmap reloader https://github.com/jimmidyson/configmap-reload) to handle all the sotry.

The service is fully compatible with coreos PrometheusRule CRD object, thus, if you decide to switch to coreos prometheus operator later, all your prometheus alerting rules will be in place.

### Usage:
```
alert-rule-ctrl is a tool that monitor PrometheusRule CRDs 
and maintain config map with rules contents. This tool is a subset of coreos prometheus operator (https://github.com/coreos/prometheus-operator)

Usage:
  alert-rule-ctrl [parameters] [flags]
  alert-rule-ctrl [command]

Available Commands:
  help        Help about any command
  version     Print version information

Flags:
      -h, --help                         help for alert-rule-ctrl

      -l, --logLevel string              Logging level,valid values: DEBUG,INFO,WARN,ERROR (default "INFO")

      --apiEndpoint string               K8S API Endpoint to connect to, if not specified, 
                                         then assumed that running inside k8s (Ignored if 'KUBECONFIG' env. var is set).
                                         Example: https://localhost:6443

      --caData string                    K8S CA data in a plain text (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)

      --caFile string                    Path to k8s CA file (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)

      --certData string                  K8S cert data in a plain text for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)

      --certFile string                  Path to k8s cert file for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)

      --keyData string                   K8S key data in a plain text for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)

      --keyFile string                   Path to k8s key file for auth. against k8s API (Ignored if 'KUBECONFIG' env. var is set or 'apiEndpoint' flag is empty)

      --tlsInsecure                      Don't verify API server's CA certificate.


      --allowedNamespace stringArray     Allowed namespace (multiple values accepted), where rules CRDs would be tracked.
                                         This is mutually exclusive with --deniedNamespace.
                                         (make sure you start under account with sufficient rights)

      --deniedNamespace stringArray      Denied namespace (multiple values accepted), where rules CRDs would NOT be tracked 
                                         This is mutually exclusive with --allowedNamespace.
                                         (make sure you start under account with sufficient rights)

      --ruleLabelsSelector stringArray   Rule labels, to select rules (multiple values accepted). Format 'key=value'

      --cmLabels stringArray             Labels to add to rules config map (multiple values accepted). Format 'key=value'

      --cmNamePrefix string              Config map name prefix, that will store alert rules (default "poarctrl")

      --cmNamespace string               Namespace to hold config map with alert rules

Use "alert-rule-ctrl [command] --help" for more information about a command.

```
