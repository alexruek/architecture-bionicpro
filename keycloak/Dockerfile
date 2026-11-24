FROM quay.io/keycloak/keycloak:21.1

# Провайдер Яндекс ID для Identity Brokering (playa-ru/keycloak-russian-providers)
# и библиотеки, которые нужны его маппингу атрибутов профиля.
ARG RUSSIAN_PROVIDERS_VERSION=1.0.49
ARG MAVEN=https://repo1.maven.org/maven2

ADD --chown=keycloak:root --chmod=644 \
    ${MAVEN}/ru/playa/keycloak/keycloak-russian-providers/${RUSSIAN_PROVIDERS_VERSION}/keycloak-russian-providers-${RUSSIAN_PROVIDERS_VERSION}.jar \
    /opt/keycloak/providers/
ADD --chown=keycloak:root --chmod=644 \
    ${MAVEN}/com/jayway/jsonpath/json-path/2.7.0/json-path-2.7.0.jar /opt/keycloak/providers/
ADD --chown=keycloak:root --chmod=644 \
    ${MAVEN}/net/minidev/json-smart/2.4.7/json-smart-2.4.7.jar /opt/keycloak/providers/
ADD --chown=keycloak:root --chmod=644 \
    ${MAVEN}/net/minidev/accessors-smart/2.4.7/accessors-smart-2.4.7.jar /opt/keycloak/providers/
