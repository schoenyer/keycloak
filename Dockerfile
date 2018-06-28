FROM inspiredag/openjdk:8-jre-alpine

COPY tmp/keycloak.tar.gz .
COPY keycloakBoot.sh .
COPY configurator/build/configurator .

RUN mkdir ./keycloak && \
    tar -xzf ./keycloak.tar.gz --strip 1 -C ./keycloak && \
    chmod -R 777 keycloak && chgrp -R 0 keycloak && chmod -R g+rwX keycloak


COPY undertow-cors-filter-0.4.0-bin.zip  ./keycloak/
COPY ./configuration/* ./keycloak/standalone/configuration/

RUN cd keycloak/ && unzip undertow-cors-filter-0.4.0-bin.zip
ENV TZ=Europe/Zurich JBOSS_HOME=/opt/app-root/keycloak/

EXPOSE 8443

CMD [ "sh", "-c", "./keycloakBoot.sh" ]
