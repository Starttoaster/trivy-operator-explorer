# Trivy Operator Explorer

This is a web explorer that scrapes the data exported by the [Trivy Operator for Kubernetes.](https://github.com/aquasecurity/trivy-operator) The Trivy Operator exports a LOT of metrics about vulnerabilities in a kubernetes cluster; so many that some people may consider not storing all of that in Prometheus because metrics with high levels of cardinality in label sets can cause query performance issues. Because of this, instead of relying on Prometheus to scrape the metrics, and have this query Prometheus, this explorer scrapes the operator's metrics itself and parses it for dashboarding.

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

- Graphical elements for setting filters, currently they're just URL query parameters.
- Add Role/ClusterRole vulnerabilities to the dashboard.
- Support different vulnerability IDs - currently GHSA vulnerabilities link to NIST just like normal CVEs, where NIST 404s.
- Add ability to connect to cluster to check for images or roles not scanned yet.
- Find out more about exposed secrets scanning. Add it to the dashboard?
- Does a JSON API make sense for this? Is there a use case for it?
- Testing. Pretty sure by law no new product has testing and it gets added later.
