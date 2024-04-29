package kube

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

const rbacAssessmentReportsResource = "rbacassessmentreports"

// GetRbacAssessmentReportList retrieves all resources of type rbacassessmentreports in all namespaces.
func GetRbacAssessmentReportList() (*v1alpha1.RbacAssessmentReportList, error) {
	var rbacList v1alpha1.RbacAssessmentReportList
	err := client.
		Get().
		Resource(rbacAssessmentReportsResource).
		Do(context.TODO()).
		Into(&rbacList)
	if err != nil {
		return nil, err
	}

	return &rbacList, nil
}

const clusterRbacAssessmentReportsResource = "clusterrbacassessmentreports"

// GetClusterRbacAssessmentReportList retrieves all resources of type clusterrbacassessmentreports in all namespaces.
func GetClusterRbacAssessmentReportList() (*v1alpha1.ClusterRbacAssessmentReportList, error) {
	var rbacList v1alpha1.ClusterRbacAssessmentReportList
	err := client.
		Get().
		Resource(clusterRbacAssessmentReportsResource).
		Do(context.TODO()).
		Into(&rbacList)
	if err != nil {
		return nil, err
	}

	return &rbacList, nil
}
