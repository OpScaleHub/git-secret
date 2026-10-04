{{/*
Chart name, truncated/sanitized for use in resource names.
*/}}
{{- define "git-secret-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. A release name that already contains the chart
name is used as-is, so `helm install git-secret-controller ...` yields
`git-secret-controller`, not `git-secret-controller-git-secret-controller`.
*/}}
{{- define "git-secret-controller.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "git-secret-controller.name" . }}
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
{{- define "git-secret-controller.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "git-secret-controller.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "git-secret-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "git-secret-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for the controller pod itself. The component label keeps
the controller's Deployment and Services from also matching the seal-UI
and publish-pubkey pods, which share name/instance.
*/}}
{{- define "git-secret-controller.controllerSelectorLabels" -}}
{{ include "git-secret-controller.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "git-secret-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- .Values.serviceAccount.name | default (include "git-secret-controller.fullname" .) }}
{{- else }}
{{- .Values.serviceAccount.name | default "default" }}
{{- end }}
{{- end }}
