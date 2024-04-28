# Trivy Operator Explorer

This is a web explorer that scrapes the data exported by the [Trivy Operator for Kubernetes.](https://github.com/aquasecurity/trivy-operator) This image runs as a single binary in a distroless container image, which means it's an extremely small footprint on your cluster too.

The Trivy Operator exports a LOT of metrics about vulnerabilities in a kubernetes cluster; so many that some may consider not storing all of that in Prometheus at all. Because of this, instead of querying Prometheus, this explorer scrapes the operator's metrics exporter itself and parses it for dashboarding. 

Note that this only reports image vulnerabilities for the time being. The Trivy Operator exports many other metrics, including reporting on potentially insecure Roles or ClusterRoles, which will be added to this explorer over time.

## Preview

![Cluster dashboard](content/index.png)

The main page lists each image that Trivy Operator has scanned in your cluster, provides a dropdown to show affected Pods which use that image. And enumerates a count of vulnerabilities for that image separated by severity. Red is critical, orange is high, yellow is medium, and blue is low. You can click on an image name to list all vulnerabilities, or click on a severity counter to see vulnerabilities of that severity for that image.

![Image dashboard](content/image.png)

This is what you see when you click on an image. All the vulnerabilities are ordered by severity level, and then by score. There are multiple filters you can apply on this page, see the filter documentation below

## Install

### Pre-requisites

This should go without saying but you'll need the [Trivy Operator](https://github.com/aquasecurity/trivy-operator) installed. Follow the documentation for installing it how you please, but I install it with helm, which lets me set a values file with the following settings:

```yaml
operator:
  # Enable all the metrics exporters
  # be aware that metrics cardinality is significantly increased with these features enabled
  # but these are what power the dashboard.
  metricsVulnIdEnabled: true
  metricsExposedSecretInfo: true
  metricsConfigAuditInfo: true
  metricsRbacAssessmentInfo: true
  metricsInfraAssessmentInfo: true
  metricsImageInfo: true
  metricsClusterComplianceInfo: true

# By default, trivy operator installs a headless Service with no Cluster IP.
# This gives it a cluster IP, allowing us to use it as the endpoint we point to in the explorer's values.
service:
  headless: false
```

### Install explorer

This assumes you installed the Trivy Operator in the `trivy-system` namespace. So edit the operator's endpoint if you installed to a different namespace.

Make a values file with at least the following:

```yaml
config:
  metrics_endpoint: 'http://trivy-operator.trivy-system.svc.cluster.local/metrics'
```

And install the helm chart with your values file:

```bash
helm upgrade --install --create-namespace \
--repo "https://starttoaster.github.io/trivy-operator-explorer" 
-n trivy-system \
--values ./values.yaml \
trivy-operator-explorer \
trivy-operator-explorer
```

## Filters

There are certain filters you can set when viewing the vulnerability list for an image. The filters are set with URL query parameters, which means the filters are share-able if you send a link to another person with any set. The current list of supported filters is below:

| Parameters   | Description                                                           | Example                   |
|--------------|-----------------------------------------------------------------------|---------------------------|
| hasfix       | Boolean to only view vulnerabilities that have a fix version, or not. | hasfix=true, hasfix=false |
| resources    | Comma-separated list of resources to view vulnerabilities for.        | resources=curl,zlib1g     |
| notresources | Comma-separated list of resources to ignore vulnerabilities for.      | notresources=curl,zlib1g  |
| severity     | Filter by level of vulnerability severity.                            | severity=Critical         |

Example URL: `http://your.explorer.install/image?hasfix=true&severity=Critical`

There are query parameters for image and digest as well, but it's not expected for them to be changed manually. These filters currently do not have a graphical toggle but there's a TODO item below to add some form elements to the page for them.

## TODO

- Add Role/ClusterRole vulnerabilities to the dashboard.
- Add exposed secrets scan results to dashboard.
- Add SBOM reports to dashboard.
- Add config audit reports to dashboard (reports on potentially insecure resource declarations.)
- Add cluster compliance reports.
- Graphical elements for setting filters, currently they're just URL query parameters.
- Testing. Pretty sure by law no new product can have tests.
