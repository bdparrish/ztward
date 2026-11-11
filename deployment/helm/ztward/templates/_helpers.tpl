{{/*
Expand the name of the chart.
*/}}
{{- define "ztward.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ztward.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ztward.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ztward.labels" -}}
helm.sh/chart: {{ include "ztward.chart" . }}
{{ include "ztward.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ztward.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ztward.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific labels
*/}}
{{- define "ztward.componentLabels" -}}
{{- $component := . -}}
app.kubernetes.io/component: {{ $component }}
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "ztward.postgresql.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "postgresql" }}
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "ztward.postgresql.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "postgresql" }}
{{- end }}

{{/*
Redis labels
*/}}
{{- define "ztward.redis.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "redis" }}
{{- end }}

{{/*
Redis selector labels
*/}}
{{- define "ztward.redis.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "redis" }}
{{- end }}

{{/*
Keycloak labels
*/}}
{{- define "ztward.keycloak.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "keycloak" }}
{{- end }}

{{/*
Keycloak selector labels
*/}}
{{- define "ztward.keycloak.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "keycloak" }}
{{- end }}

{{/*
Platform labels
*/}}
{{- define "ztward.platform.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "platform" }}
{{- end }}

{{/*
Platform selector labels
*/}}
{{- define "ztward.platform.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "platform" }}
{{- end }}

{{/*
Key Manager labels
*/}}
{{- define "ztward.keyManager.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "key-manager" }}
{{- end }}

{{/*
Key Manager selector labels
*/}}
{{- define "ztward.keyManager.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "key-manager" }}
{{- end }}

{{/*
Key Access labels
*/}}
{{- define "ztward.keyAccess.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "key-access" }}
{{- end }}

{{/*
Key Access selector labels
*/}}
{{- define "ztward.keyAccess.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "key-access" }}
{{- end }}

{{/*
PAP labels
*/}}
{{- define "ztward.pap.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "pap" }}
{{- end }}

{{/*
PAP selector labels
*/}}
{{- define "ztward.pap.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "pap" }}
{{- end }}

{{/*
PAP UI labels
*/}}
{{- define "ztward.papUI.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "pap-ui" }}
{{- end }}

{{/*
PAP UI selector labels
*/}}
{{- define "ztward.papUI.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "pap-ui" }}
{{- end }}

{{/*
Envoy labels
*/}}
{{- define "ztward.envoy.labels" -}}
{{ include "ztward.labels" . }}
{{ include "ztward.componentLabels" "envoy" }}
{{- end }}

{{/*
Envoy selector labels
*/}}
{{- define "ztward.envoy.selectorLabels" -}}
{{ include "ztward.selectorLabels" . }}
{{ include "ztward.componentLabels" "envoy" }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "ztward.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return the proper image name
*/}}
{{- define "ztward.image" -}}
{{- $registryName := .registry -}}
{{- $repositoryName := .repository -}}
{{- $tag := .tag | toString -}}
{{- if .global }}
    {{- if and .global.imageRegistry (eq .registry "") }}
        {{- $registryName = .global.imageRegistry -}}
    {{- end -}}
{{- end -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Utility BusyBox image used by init containers
*/}}
{{- define "ztward.busyboxImage" -}}
{{- $registryPrefix := "" -}}
{{- if .Values.global.imageRegistry }}
  {{- $registryPrefix = printf "%s/" .Values.global.imageRegistry -}}
{{- end }}
{{- printf "%sbusybox:1.36" $registryPrefix -}}
{{- end }}

{{/*
Cluster domain helper (defaults to cluster.local)
*/}}
{{- define "ztward.clusterDomain" -}}
{{- default "cluster.local" .Values.global.clusterDomain -}}
{{- end }}

{{/*
Secret name helpers (support external/managed secrets)
*/}}
{{- define "ztward.ztwardSecretName" -}}
{{- default (printf "%s-ztward-secret" (include "ztward.fullname" .)) .Values.secrets.ztward.name -}}
{{- end }}

{{- define "ztward.keycloakSecretName" -}}
{{- default (printf "%s-keycloak-secret" (include "ztward.fullname" .)) .Values.secrets.keycloak.name -}}
{{- end }}

{{- define "ztward.postgresqlSecretName" -}}
{{- default (printf "%s-postgresql-secret" (include "ztward.fullname" .)) .Values.secrets.postgresql.name -}}
{{- end }}

{{/*
Shared external egress rule for network policies
*/}}
{{- define "ztward.networkPolicy.externalEgress" -}}
{{- $np := .Values.security.networkPolicy }}
{{- if and $np.externalEgress.enabled $np.externalEgress.cidrs }}
- to:
  {{- range $np.externalEgress.cidrs }}
  - ipBlock:
      cidr: {{ . }}
  {{- end }}
  ports:
  {{- range $np.externalEgress.ports }}
  - protocol: TCP
    port: {{ . }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Fully qualified hostname for the bundled PostgreSQL service
*/}}
{{- define "ztward.postgresql.host" -}}
{{- $domain := include "ztward.clusterDomain" . -}}
{{- printf "%s.%s.svc.%s" (include "ztward.postgresql.serviceName" .) .Release.Namespace $domain -}}
{{- end }}

{{/*
Return the proper Storage Class
*/}}
{{- define "ztward.storageClass" -}}
{{- $storageClass := .storageClass -}}
{{- if .global -}}
    {{- if .global.storageClass -}}
        {{- $storageClass = .global.storageClass -}}
    {{- end -}}
{{- end -}}
{{- if $storageClass -}}
storageClassName: {{ $storageClass | quote }}
{{- end -}}
{{- end -}}

{{/*
Service names
*/}}
{{- define "ztward.postgresql.serviceName" -}}
{{- printf "%s-postgresql" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.redis.serviceName" -}}
{{- printf "%s-redis" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.keycloak.serviceName" -}}
{{- printf "%s-keycloak" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.keycloak.realm" -}}
{{- default "ztward" .Values.keycloak.realm -}}
{{- end }}

{{- define "ztward.keycloak.issuerURL" -}}
{{- $realm := include "ztward.keycloak.realm" . -}}
{{- if .Values.keycloak.config.issuerURL }}
{{- .Values.keycloak.config.issuerURL -}}
{{- else if and .Values.keycloak.ingress.enabled .Values.keycloak.config.hostname }}
{{- printf "https://%s/realms/%s" .Values.keycloak.config.hostname $realm -}}
{{- else -}}
{{- printf "http://%s:%v/realms/%s" (include "ztward.keycloak.serviceName" .) .Values.keycloak.service.port $realm -}}
{{- end }}
{{- end }}

{{- define "ztward.platform.serviceName" -}}
{{- printf "%s-platform" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.keyManager.serviceName" -}}
{{- printf "%s-key-manager" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.keyAccess.serviceName" -}}
{{- printf "%s-key-access" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.pap.serviceName" -}}
{{- printf "%s-pap" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.papUI.serviceName" -}}
{{- printf "%s-pap-ui" (include "ztward.fullname" .) }}
{{- end }}

{{- define "ztward.envoy.serviceName" -}}
{{- printf "%s-envoy" (include "ztward.fullname" .) }}
{{- end }}
