# Trivy Operator Explorer

## Usage

This is still heavily in progress. This is just local dev usage for now. Assuming your Trivy Operator installation is in the trivy-system namespace, in one shell:
```
kubectl port-forward  -n trivy-system service/trivy-operator 8081:80
```

Then in another shell window:
```
export TRIVY_OPERATOR_EXPLORER_METRICS_ENDPOINT="http://localhost:8081/metrics"
go generate && go build && ./trivy-operator-explorer
```

## TODO

- Add role vulnerabilities to the dashboard
- Support GHSA CVE links in the image vulnerability view

### Filters

#### Images

- Filter images view by affected namespace.

#### Image/Vulnerability List

- Filter by resource, or not-resource
- Filter out vulnerabilities that don't have a fix version
- Add graphical ability to filter by Severity, currently it's just a query param

## Future TODO

Things that I'm probably not doing right away but might be worth doing.

- Add ability to connect to cluster to check for images or roles not scanned yet.
- Have an endpoint and view for each affected Pod that shows other data like its role.
- Find out more about exposed secrets scanning.
