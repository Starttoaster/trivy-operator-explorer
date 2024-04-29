package kube

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

const configAuditReportsResource = "configauditreports"

// GetConfigAuditReportList retrieves all resources of type configauditreport in all namespaces.
func GetConfigAuditReportList() (*v1alpha1.ConfigAuditReportList, error) {
	var list v1alpha1.ConfigAuditReportList
	err := client.
		Get().
		Resource(configAuditReportsResource).
		Do(context.TODO()).
		Into(&list)
	if err != nil {
		return nil, err
	}

	return &list, nil
}
