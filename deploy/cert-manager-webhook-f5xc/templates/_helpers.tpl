{{/* vim: set filetype=mustache: */}}
{{- define "cert-manager-webhook-f5xc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cert-manager-webhook-f5xc.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "cert-manager-webhook-f5xc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cert-manager-webhook-f5xc.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "cert-manager-webhook-f5xc.fullname" .) }}
{{- end -}}

{{- define "cert-manager-webhook-f5xc.rootCAIssuer" -}}
{{ printf "%s-ca" (include "cert-manager-webhook-f5xc.fullname" .) }}
{{- end -}}

{{- define "cert-manager-webhook-f5xc.rootCACertificate" -}}
{{ printf "%s-ca" (include "cert-manager-webhook-f5xc.fullname" .) }}
{{- end -}}

{{- define "cert-manager-webhook-f5xc.servingCertificate" -}}
{{ printf "%s-webhook-tls" (include "cert-manager-webhook-f5xc.fullname" .) }}
{{- end -}}
