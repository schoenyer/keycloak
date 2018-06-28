ifndef VERSION
VERSION=$(shell cat version)
endif

DEVREPO=dev.docker.inspired.ag
PUBREPO=dev.docker.inspired.ag

NAME = platform/keycloak

KEYCLOAKVERSION = 3.4.3.Final

ifeq ($(subst -SNAPSHOT,,$(VERSION)),$(VERSION))
	# Release
	REPO = $(PUBREPO)
else
	# Snapshot
	REPO = $(DEVREPO)
endif

URI=$(REPO)/$(NAME)

.PHONY: keycloak clean image fast push configurator

all: clean format image
all_local: clean format image

configurator:
	rm -rf ./configurator/build & docker run --rm -it -e CGO_ENABLED=0 -v "$(PWD)/configurator":/usr/src/myapp -w /usr/src/myapp golang:1.9-alpine sh -c "apk --no-cache add git make bash gcc musl-dev linux-headers curl && mkdir build && cd ./build && go build -ldflags '-linkmode external -extldflags \"-static\"' -tags netgo ../configurator.go"

keycloak:
	test -d tmp || mkdir tmp
	test ! -f tmp/keycloak.tar.gz && curl https://downloads.jboss.org/keycloak/$(KEYCLOAKVERSION)/keycloak-$(KEYCLOAKVERSION).tar.gz -o tmp/keycloak.tar.gz || true

image: keycloak configurator
	docker build -t $(URI):$(VERSION) --rm=true --no-cache=true --force-rm=true .

image_it: keycloak configurator
	docker build -t keycloak:it --rm=true --no-cache=true --force-rm=true .

fast:
	docker build -t $(URI):$(VERSION) .

run: image
	docker run -ti -p 8443:8443 -p 8080:8080 -p 9990:9990 -e KEYCLOAK_PASSWORD=admin -e KEYCLOAK_REALM=default -e KEYCLOAK_TRUSTED="*.i.test" -e PKCS12_ALIAS=1 $(URI):$(VERSION)

push: image
	docker push $(URI):$(VERSION)

clean:
	rm -rf ./tmp
	rm -rf ./configurator/build
