package kube

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

const clusterInfraAssessmentResource = "clusterinfraassessmentreports"

// GetClusterInfraAssessmentReportList retrieves all resources of type clusterinfraassessmentreport in all namespaces.
func GetClusterInfraAssessmentReportList() (*v1alpha1.ClusterInfraAssessmentReportList, error) {
	var list v1alpha1.ClusterInfraAssessmentReportList
	err := client.
		Get().
		Resource(clusterInfraAssessmentResource).
		Do(context.TODO()).
		Into(&list)
	if err != nil {
		return nil, err
	}

	return &list, nil
}
