{{- define "kbomination.name" -}}kbomination{{- end -}}
{{- define "kbomination.labels" -}}
app.kubernetes.io/name: {{ include "kbomination.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
