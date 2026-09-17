{{- define "traversal-connector.name" -}}
{{- default "traversal-connector" .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "traversal-connector.fullname" -}}
{{- if contains .Release.Name .Chart.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name "traversal-connector" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "traversal-connector.labels" -}}
app.kubernetes.io/name: {{ include "traversal-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "traversal-connector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "traversal-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "traversal-connector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "traversal-connector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "traversal-connector.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag -}}
{{- end -}}

{{- /* Whether the forwarder sidecar is part of this release, as a non-empty
       string for truth. disableTelemetry is the master switch: it silences the
       forwarder too, so opting out never also requires opting out of the sidecar
       it feeds. Both the pod and its config must agree, or a disabled release
       leaves an orphaned ConfigMap behind. */}}
{{- define "traversal-connector.sidecarEnabled" -}}
{{- if and .Values.otel.sidecar.enabled (not .Values.disableTelemetry) -}}
true
{{- end -}}
{{- end -}}

{{- /* Resolved OTLP endpoint for one signal ("metrics" | "traces" | "logs"),
       falling back to Traversal's hosted ingest when unset.

       The default's shape follows the transport: OTLP/gRPC takes a host:port and
       names the signal in the request, while OTLP/HTTP names it in the path. The
       forwarder sidecar egresses over gRPC regardless of otel.protocol — that
       setting governs only the in-pod loopback hop — so an enabled sidecar pins
       the gRPC form. */}}
{{- define "traversal-connector.otlpEndpoint" -}}
{{- $otel := .root.Values.otel -}}
{{- $explicit := index $otel (printf "%sEndpoint" .signal) -}}
{{- if $explicit -}}
{{- $explicit -}}
{{- else if or (include "traversal-connector.sidecarEnabled" .root) (not (hasPrefix "http/" $otel.protocol)) -}}
https://telemetry.traversal.com:4317
{{- else -}}
https://telemetry.traversal.com/v1/{{ .signal }}
{{- end -}}
{{- end -}}
