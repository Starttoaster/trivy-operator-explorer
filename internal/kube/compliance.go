package kube

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

const complianceReportListResource = "clustercompliancereports"

// GetComplianceReportList retrieves all resources of type compliance in all namespaces.
func GetComplianceReportList() (*v1alpha1.ClusterComplianceReportList, error) {
	var list v1alpha1.ClusterComplianceReportList
	err := client.
		Get().
		Resource(complianceReportListResource).
		Do(context.TODO()).
		Into(&list)
	if err != nil {
		return nil, err
	}

	return &list, nil
}
