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

{{- /* Capability trust, as the connector requires it at startup
       (TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_ROOTS; keys need
       TRAVERSAL_CAPABILITY_ISSUER): refused at render rather than found as a
       crash-looping pod. */}}
{{- define "traversal-connector.validateCapabilityTrust" -}}
{{- $pipes := .Values.pipes | default dict -}}
{{- $roots := $pipes.trustedRoots | default dict -}}
{{- $keys := $pipes.capabilityKeys | default "" | toString | trim -}}
{{- if not (or ($roots.current | default "" | trim) $keys) -}}
{{- fail "pipes.trustedRoots.current or pipes.capabilityKeys is required: the connector trusts no capability without one." -}}
{{- end -}}
{{- if and $keys (not ($pipes.capabilityIssuer | default "" | toString | trim)) -}}
{{- fail "pipes.capabilityIssuer is required with pipes.capabilityKeys." -}}
{{- end -}}
{{- end -}}

{{- /* The connector's identity, as it requires it at startup: a lower-case
       UUID connectorID (rawpipe.IsConnectorID), and controllerTLS's client
       certificate and key, without which no tunnel opens. A 0.9.x values
       file lacking either fails here, at render, rather than as a
       crash-looping rollout. */}}
{{- define "traversal-connector.validateIdentity" -}}
{{- $id := required "connectorID is required" .Values.connectorID | toString -}}
{{- if not (regexMatch `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` $id) -}}
{{- fail "connectorID must be the lower-case UUID Traversal provided, such as 6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00: connector 0.10.x refuses any other form." -}}
{{- end -}}
{{- $tls := .Values.controllerTLS | default dict -}}
{{- if not (or $tls.existingSecret (and $tls.certPEM $tls.keyPEM)) -}}
{{- fail "controllerTLS is required: set controllerTLS.existingSecret, or controllerTLS.certPEM and controllerTLS.keyPEM. Connector 0.10.x opens its tunnels with that client certificate." -}}
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
