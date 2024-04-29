# Trivy Operator Explorer

This is a web explorer that displays the reports generated by the [Trivy Operator for Kubernetes.](https://github.com/aquasecurity/trivy-operator)

## Preview

![Dashboard](content/preview.gif)

## Install

### Pre-requisites

You will of course need [Trivy Operator](https://github.com/aquasecurity/trivy-operator) already installed. The latest version of this explorer should work with the latest version of Trivy Operator. This explorer gets its data directly from the reporting custom resources that Trivy Operator installs in the cluster, and updates as it runs its scans.

### Install explorer

Install with the helm chart:

```bash
helm upgrade --install --create-namespace \
--repo "https://starttoaster.github.io/trivy-operator-explorer" 
-n trivy-explorer \
trivy-operator-explorer \
trivy-operator-explorer
```

## Filters

Some dashboards have filters available. These filters are only set-able from the URL in query parameters for now, as there are no forms on the explorer yet, though it is planned.

### Image filter

| Parameters   | Description                                                           | Example                   |
|--------------|-----------------------------------------------------------------------|---------------------------|
| hasfix       | Boolean to only view vulnerabilities that have a fix version, or not. | hasfix=true, hasfix=false |
| resources    | Comma-separated list of resources to view vulnerabilities for.        | resources=curl,zlib1g     |
| notresources | Comma-separated list of resources to ignore vulnerabilities for.      | notresources=curl,zlib1g  |
| severity     | Filter by level of vulnerability severity.                            | severity=Critical         |

Example URL: `http://your.explorer.install/image?hasfix=true&severity=Critical`

There are query parameters for image and digest as well, but it's not expected for them to be changed manually. These filters currently do not have a graphical toggle but there's a TODO item below to add some form elements to the page for them.

### ClusterRole/Role filter

| Parameters   | Description                                                           | Example                   |
|--------------|-----------------------------------------------------------------------|---------------------------|
| severity     | Filter by level of vulnerability severity.                            | severity=Critical         |

Example URL: `http://your.explorer.install/role?severity=Critical`

## TODO

- Add exposed secrets scan results to dashboard.
- Add SBOM reports to dashboard.
- Add config audit reports to dashboard (reports on potentially insecure resource declarations.)
- Add cluster compliance reports.
- Make a home page that displays useful graphs for each of the report types.
- Graphical elements for setting filters, currently they're just URL query parameters.
- Testing. Pretty sure by law no new product can have tests.
