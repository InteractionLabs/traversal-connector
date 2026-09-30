{{- define "traversal-connector.name" -}}
{{- default "traversal-connector" .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /* Validate a routing-only host:port. Bracketed IPv6 (including zone IDs),
       IPv4, and DNS are accepted. The value is deliberately not included in
       errors because malformed input may contain credentials. */}}
{{- define "traversal-connector.validateConnectTo" -}}
{{- $name := .name -}}
{{- $address := .address | default "" -}}
{{- if $address -}}
{{- if not (regexMatch `^([^:/?#@[:space:]]+|\[[0-9A-Za-z_.:%-]+\]):[0-9]+$` $address) -}}
{{- fail (printf "%s must be a host:port (DNS, IPv4, or bracketed IPv6) without a scheme, path, query, fragment, or credentials." $name) -}}
{{- end -}}
{{- $port := regexFind `[0-9]+$` $address | atoi -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s port must be from 1 to 65535." $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "traversal-connector.urlAuthority" -}}
{{- regexReplaceAll `^https://([^/]+).*$` . `${1}` -}}
{{- end -}}

{{- define "traversal-connector.authorityHostname" -}}
{{- $authority := . -}}
{{- if hasPrefix "[" $authority -}}
{{- regexReplaceAll `^\[([^]]+)\](?::[0-9]+)?$` $authority `${1}` -}}
{{- else -}}
{{- first (splitList ":" $authority) -}}
{{- end -}}
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

{{/*
goDurationSeconds parses a single-unit Go duration (30s, 15m, 4h) into seconds.
Sub-second units fail. The connector process rejects those timeouts at startup,
so the chart rejects them at render.
*/}}
{{- define "traversal-connector.goDurationSeconds" -}}
{{- $name := .name -}}
{{- $v := .value | toString -}}
{{- if not (regexMatch "^[1-9][0-9]*(ns|us|µs|ms|s|m|h)$" $v) -}}
{{- fail (printf "%s must be a positive duration with one unit (examples: 30s, 15m, 4h), got %q" $name $v) -}}
{{- end -}}
{{- $n := regexFind "^[0-9]+" $v | atoi -}}
{{- $unit := regexFind "(ns|us|µs|ms|s|m|h)$" $v -}}
{{- if or (eq $unit "ns") (eq $unit "us") (eq $unit "µs") (eq $unit "ms") -}}
{{- fail (printf "%s must be at least 1s, got %q" $name $v) -}}
{{- else if eq $unit "h" -}}
{{- mul $n 3600 -}}
{{- else if eq $unit "m" -}}
{{- mul $n 60 -}}
{{- else -}}
{{- $n -}}
{{- end -}}
{{- end -}}

{{- /* The trusted keys packaged for rawTunnel.environment, as YAML, or an
       empty map when the chart has none for it. */}}
{{- define "traversal-connector.rawTunnelKeys" -}}
{{- get .Values.rawTunnel.trustedKeys (.Values.rawTunnel.environment | default "") | default dict | toYaml -}}
{{- end -}}
