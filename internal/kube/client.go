package kube

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var client *rest.RESTClient
var coreClient *rest.RESTClient

// InitClient initializes the Kubernetes client based on the provided configuration.
// If inCluster is true, it uses in-cluster configuration; otherwise, it uses the kubeconfig file.
func InitClient(inCluster bool, kubeconfigPath string) error {
	var config *rest.Config
	var err error

	if inCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("error getting in-cluster config: %w", err)
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return fmt.Errorf("error getting out-of-cluster config: %w", err)
		}
	}

	err = v1alpha1.AddToScheme(scheme.Scheme)
	if err != nil {
		return fmt.Errorf("error adding to scheme: %w", err)
	}

	crdConfig := *config
	crdConfig.ContentConfig.GroupVersion = &v1alpha1.SchemeGroupVersion
	crdConfig.APIPath = "/apis"
	crdConfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	crdConfig.UserAgent = rest.DefaultKubernetesUserAgent()

	clientset, err := rest.UnversionedRESTClientFor(&crdConfig)
	if err != nil {
		return fmt.Errorf("error creating clientset from config: %w", err)
	}

	client = clientset

	// Client for core Kubernetes resources (pods, services, etc.)
	coreConfig := *config
	coreConfig.ContentConfig.GroupVersion = &corev1.SchemeGroupVersion
	coreConfig.APIPath = "/api"
	coreConfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	coreConfig.UserAgent = rest.DefaultKubernetesUserAgent()

	coreClientset, err := rest.RESTClientFor(&coreConfig)
	if err != nil {
		return fmt.Errorf("error creating core clientset from config: %w", err)
	}

	coreClient = coreClientset

	return nil
}
