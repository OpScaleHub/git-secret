{{/*
Chart name, truncated/sanitized for use in resource names.
*/}}
{{- define "keyfold.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. A release name that already contains the chart
name is used as-is, so `helm install keyfold ...` yields
`keyfold`, not `keyfold-keyfold`.
*/}}
{{- define "keyfold.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "keyfold.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "keyfold.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "keyfold.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "keyfold.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keyfold.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for the controller pod itself. The component label keeps
the controller's Deployment and Services from also matching the seal-UI
and publish-pubkey pods, which share name/instance.
*/}}
{{- define "keyfold.controllerSelectorLabels" -}}
{{ include "keyfold.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "keyfold.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- .Values.serviceAccount.name | default (include "keyfold.fullname" .) }}
{{- else }}
{{- .Values.serviceAccount.name | default "default" }}
{{- end }}
{{- end }}
