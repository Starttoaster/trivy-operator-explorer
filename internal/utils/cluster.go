package utils

// ClusterLabel is the ObjectMeta label the frontend stamps onto every report
// item as it is loaded from S3 so that views can attribute a row to the cluster
// it came from. It is intentionally namespaced to avoid colliding with the
// labels trivy-operator itself sets on its custom resources.
const ClusterLabel = "trivy-operator-explorer/cluster"
