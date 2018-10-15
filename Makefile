ifndef VERSION
VERSION=$(shell cat version)
endif

REPO=schoenyer

NAME=keycloak

KEYCLOAKVERSION = 3.4.3.Final

URI=$(REPO)/$(NAME)

.PHONY: keycloak clean image fast push configurator

all: clean format image
all_local: clean format image

configurator:
	rm -rf ./configurator/build & docker run --rm -it -e CGO_ENABLED=0 -v "$(PWD)/configurator":/usr/src/myapp -w /usr/src/myapp golang:1.9-alpine sh -c "apk --no-cache add git make bash gcc musl-dev linux-headers curl && go get github.com/sirupsen/logrus && mkdir -p build && cd ./build && go build -ldflags '-linkmode external -extldflags \"-static\"' -tags netgo ../configurator.go"

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
