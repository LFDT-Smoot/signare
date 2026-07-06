SHELL=/bin/bash -o pipefail

DOCKER_TAG ?= local
ARTIFACT_NAME ?= "signare"
DOCKER_IMAGE_NAME ?= ${ARTIFACT_NAME}

COMMIT ?= $(shell git rev-parse --short HEAD)
BUILD_TIME ?= $(shell date -u +%s)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
TAG ?= $(shell git tag --points-at HEAD)

define goBuild
        $(eval artifactName = $1)
        $(eval ldflags = $2)
        $(eval os = $3)
        $(eval extension = $4)
        $(eval cgo = $5)
        $(eval osSuffix = _$(os))
        CGO_ENABLED=$(cgo) GOOS=$(os) GOARCH=amd64 go build -ldflags=$(ldflags) -o bin/$(artifactName)$(osSuffix)_amd64$(extension) ./cmd/$(artifactName)/$(artifactName).go
endef

# STANDARDISED STEPS
.PHONY: build
build:
	$(eval ldflags = "-X main.commitHash=$(COMMIT) -X main.buildTime=$(BUILD_TIME) -X main.branch=$(BRANCH) -X main.tag=$(TAG)")

	$(call goBuild, signare, $(ldflags), linux,,1)

.PHONY: lint
lint:
	@echo "Executing linters"
	golangci-lint --verbose run

.PHONY: unit_test
unit_test:
	@echo "Not applicable"

.PHONY: integration_test
integration_test:
	@echo "Not applicable"

## CI Tasks
.PHONY: ci.docker_build
ci.docker_build:
	@echo "Building docker image"
	docker buildx build --load --progress plain \
		--build-arg GOPROXY=${GOPROXY} \
		--build-arg COMMIT=${COMMIT} \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg BRANCH=${BRANCH} \
		--build-arg TAG=${TAG} \
		-t ${DOCKER_IMAGE_NAME}:${DOCKER_TAG} \
		-f ../app/Dockerfile \
		../

## tools tasks
.PHONY: tools.format
tools.format:
	@echo ">> Formatting"
	@goimports -w -local "github.com/hyperledger-labs" .
