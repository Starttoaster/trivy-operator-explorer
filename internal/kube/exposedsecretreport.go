package kube

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

const exposedSecretReportsResource = "exposedsecretreports"

// GetExposedSecretReportList retrieves all resources of type exposedsecretreports in all namespaces.
func GetExposedSecretReportList() (*v1alpha1.ExposedSecretReportList, error) {
	var list v1alpha1.ExposedSecretReportList
	err := client.
		Get().
		Resource(exposedSecretReportsResource).
		Do(context.TODO()).
		Into(&list)
	if err != nil {
		return nil, err
	}

	return &list, nil
}
