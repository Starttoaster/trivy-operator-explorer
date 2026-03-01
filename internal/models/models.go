package models

// ClusterReport is the top-level payload an agent sends to the central API.
// It contains all normalized trivy-operator data for a single cluster.
type ClusterReport struct {
	ClusterName            string                        `json:"cluster_name"`
	Vulnerabilities        []VulnerabilityReport         `json:"vulnerabilities"`
	ConfigAudits           []ConfigAuditReport           `json:"config_audits"`
	ClusterInfraAudits     []ClusterInfraAuditReport     `json:"cluster_infra_audits"`
	RbacAssessments        []RbacAssessmentReport        `json:"rbac_assessments"`
	ClusterRbacAssessments []ClusterRbacAssessmentReport `json:"cluster_rbac_assessments"`
	ExposedSecrets         []ExposedSecretReport         `json:"exposed_secrets"`
	ComplianceReports      []ComplianceReport            `json:"compliance_reports"`
}

// VulnerabilityReport represents a single trivy-operator VulnerabilityReport,
// normalized to be independent of the K8s CRD types.
type VulnerabilityReport struct {
	Registry          string          `json:"registry"`
	Repository        string          `json:"repository"`
	Tag               string          `json:"tag"`
	Digest            string          `json:"digest"`
	OSFamily          string          `json:"os_family"`
	OSVersion         string          `json:"os_version"`
	OSEOSL            bool            `json:"os_eosl"`
	ResourceKind      string          `json:"resource_kind"`
	ResourceName      string          `json:"resource_name"`
	ResourceNamespace string          `json:"resource_namespace"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a single CVE finding.
type Vulnerability struct {
	CVEID            string  `json:"cve_id"`
	Severity         string  `json:"severity"`
	Score            float64 `json:"score"`
	URL              string  `json:"url"`
	Resource         string  `json:"resource"`
	Title            string  `json:"title"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
}

// ConfigAuditReport represents a trivy-operator ConfigAuditReport for a
// namespaced K8s resource (Deployment, StatefulSet, etc.).
type ConfigAuditReport struct {
	Name      string             `json:"name"`
	Namespace string             `json:"namespace"`
	Kind      string             `json:"kind"`
	Checks    []ConfigAuditCheck `json:"checks"`
}

// ConfigAuditCheck is a single finding within a ConfigAuditReport.
type ConfigAuditCheck struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ClusterInfraAuditReport represents a trivy-operator ClusterInfraAssessmentReport.
type ClusterInfraAuditReport struct {
	Name   string                   `json:"name"`
	Kind   string                   `json:"kind"`
	Checks []ClusterInfraAuditCheck `json:"checks"`
}

// ClusterInfraAuditCheck is a single finding within a ClusterInfraAuditReport.
type ClusterInfraAuditCheck struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// RbacAssessmentReport represents a trivy-operator RbacAssessmentReport
// for a namespaced Role or RoleBinding.
type RbacAssessmentReport struct {
	Name      string                `json:"name"`
	Namespace string                `json:"namespace"`
	Kind      string                `json:"kind"`
	Checks    []RbacAssessmentCheck `json:"checks"`
}

// RbacAssessmentCheck is a single finding within an RbacAssessmentReport.
type RbacAssessmentCheck struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ClusterRbacAssessmentReport represents a trivy-operator ClusterRbacAssessmentReport
// for a cluster-scoped ClusterRole or ClusterRoleBinding.
type ClusterRbacAssessmentReport struct {
	Name   string                       `json:"name"`
	Kind   string                       `json:"kind"`
	Checks []ClusterRbacAssessmentCheck `json:"checks"`
}

// ClusterRbacAssessmentCheck is a single finding within a ClusterRbacAssessmentReport.
type ClusterRbacAssessmentCheck struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ExposedSecretReport represents a trivy-operator ExposedSecretReport for an image.
type ExposedSecretReport struct {
	ImageName         string          `json:"image_name"`
	ImageDigest       string          `json:"image_digest"`
	ResourceKind      string          `json:"resource_kind"`
	ResourceName      string          `json:"resource_name"`
	ResourceNamespace string          `json:"resource_namespace"`
	Secrets           []ExposedSecret `json:"secrets"`
}

// ExposedSecret is a single secret finding.
type ExposedSecret struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Target   string `json:"target"`
	Match    string `json:"match"`
}

// ComplianceReport represents a trivy-operator ClusterComplianceReport.
type ComplianceReport struct {
	ReportID  string              `json:"report_id"`
	Title     string              `json:"title"`
	FailCount int                 `json:"fail_count"`
	PassCount int                 `json:"pass_count"`
	Controls  []ComplianceControl `json:"controls"`
}

// ComplianceControl is a single control within a ComplianceReport.
type ComplianceControl struct {
	IDNumber    string              `json:"id_number"`
	CheckIDs    []ComplianceCheckID `json:"check_ids"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Severity    string              `json:"severity"`
	TotalFailed *int                `json:"total_failed,omitempty"`
}

// ComplianceCheckID is an individual check reference within a control.
type ComplianceCheckID struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}
