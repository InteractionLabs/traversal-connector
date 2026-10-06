{{- define "traversal-connector.redactionEnabled" -}}
{{- if not (kindIs "bool" .Values.redaction.enabled) -}}
{{- fail "redaction.enabled must be a boolean" -}}
{{- end -}}
{{- if not (kindIs "bool" .Values.configUpdates.enabled) -}}
{{- fail "configUpdates.enabled must be a boolean" -}}
{{- end -}}
{{- $sources := list .Values.redaction.rulesContent .Values.redactionRules .Values.redaction.existingConfigMap .Values.redaction.existingSecret | compact -}}
{{- $enabled := or .Values.redaction.enabled (not (empty .Values.redactionRules)) -}}
{{- if and .Values.configUpdates.enabled (or $enabled (gt (len $sources) 0)) -}}
{{- fail "Local redaction and configUpdates.enabled=true are mutually exclusive" -}}
{{- end -}}
{{- if and (not $enabled) (gt (len $sources) 0) -}}
{{- fail "Local redaction sources require redaction.enabled=true" -}}
{{- end -}}
{{- if $enabled -}}
{{- if ne (len $sources) 1 -}}
{{- fail "Local redaction requires exactly one source: rulesContent, existingConfigMap, existingSecret, or legacy redactionRules" -}}
{{- end -}}
true
{{- end -}}
{{- end -}}
