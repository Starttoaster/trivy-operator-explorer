package views

const (
	// TrivyImageVulnerabilityMetricName the metric key for image vulnerability data
	TrivyImageVulnerabilityMetricName = "trivy_vulnerability_id"

	// TrivyImageInfoMetricName gives info on the images running in the cluster like base distro
	TrivyImageInfoMetricName = "trivy_image_info"

	// TrivyRbacAssessmentMetricName gives info on potentially over-giving rbac Roles/ClusterRoles
	TrivyRbacAssessmentMetricName = "trivy_rbacassessments_info"

	// TrivyRbacAssessmentCountersMetricName gives counters of rbac issues for each Role/ClusterRole by severity
	TrivyRbacAssessmentCountersMetricName = "trivy_role_rbacassessments"

	// TrivyConfigAuditsMetricName gives info on in-cluster resource compliance tests
	TrivyConfigAuditsMetricName = "trivy_configaudits_info"

	// TrivyConfigAuditsCountersMetricName gives counters of in-cluster resource compliance test failures by resource and by severity
	TrivyConfigAuditsCountersMetricName = "trivy_resource_configaudits"

	// TrivyExposedSecretsMetricName gives info on discovered exposed secrets in images
	TrivyExposedSecretsMetricName = "trivy_exposedsecrets_info"

	// TrivyExposedSecretsCountersMetricName gives counters on discovered exposed secrets by image and by severity
	TrivyExposedSecretsCountersMetricName = "trivy_image_exposedsecrets"

	// TrivyClusterComplianceMetricName gives pass/fail outcomes on cluster compliance tests, usually for control plane components
	TrivyClusterComplianceMetricName = "trivy_compliance_info"
)
