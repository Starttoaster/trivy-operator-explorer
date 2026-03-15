{{/*
Expand the name of the chart.
*/}}
{{- define "server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "server.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "server.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: trivy-operator-explorer
{{- end }}

{{- define "server.dbDsn" -}}
{{- if .Values.database.existingSecret }}
- name: TRIVY_API_DB_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.existingSecretKey }}
{{- else }}
- name: TRIVY_API_DB_DSN
  value: {{ .Values.database.dsn | quote }}
{{- end }}
{{- end }}

{{- define "frontend.dbDsn" -}}
{{- if .Values.database.existingSecret }}
- name: TRIVY_OPERATOR_EXPLORER_DB_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.existingSecretKey }}
{{- else }}
- name: TRIVY_OPERATOR_EXPLORER_DB_DSN
  value: {{ .Values.database.dsn | quote }}
{{- end }}
{{- end }}
