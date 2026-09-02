SHELL=/bin/bash -o pipefail

GIT_ROOT_DIR=$(shell git rev-parse --show-toplevel)
ARTIFACTS_DIR ?= ${GIT_ROOT_DIR}/_artifacts
CURDIR := $(shell pwd)
SIGNARE_DOCS="signare-docs"

define postProcess
	$(eval artifactName=$1)
	$(eval pkgFrom=$2)
	$(eval pkgTo=$3)

	@echo "Modify coverage files go paths so that they are relative to the base directory used for Sonar coverage"
	find $(ARTIFACTS_DIR) -type f -name '$(artifactName)*.coverage.out' | while read file; do \
		sed -i 's|$(pkgFrom)|$(pkgTo)|g' $$file; \
	done
endef

# STANDARDISED STEPS
.PHONY: build
build:
	@echo "Not applicable"

.PHONY: lint
lint:
	@echo "Executing linters"
	golangci-lint --verbose run

.PHONY: unit_test
unit_test:
	@echo "Creating artifacts dir"
	mkdir -p ${ARTIFACTS_DIR}
	@echo "Executing tests for application packages"
	gotestsum --jsonfile ${ARTIFACTS_DIR}/unit_tests_results.json --format short-verbose --junitfile ${ARTIFACTS_DIR}/junit.xml -- -p 1 -tags=unit -timeout=5m -coverpkg=github.com/lfdt-smoot/signare/app/pkg/... -coverprofile=${ARTIFACTS_DIR}/signare.coverage.out github.com/lfdt-smoot/signare/app/pkg/...
	$(call postProcess, signare, github.com/lfdt-smoot/signare/app, app)

.PHONY: race_test
race_test:
	@echo "Executing tests with the race detector"
	go test -race -p 1 -timeout=10m github.com/lfdt-smoot/signare/app/pkg/...

.PHONY: integration_test
integration_test:
	@echo "Not applicable"

## CI Tasks
.PHONY: ci.docker_build
ci.docker_build:
	@echo "Not applicable"

## tools tasks

.PHONY: tools.bundle_api
tools.bundle_api:
	@echo "Generating the API spec bundle"
	@redocly bundle --ext yaml docs/open-api-specs/signare-api/index.yaml -o docs/open-api-specs/signare-api/index_bundled_openapi.yaml

.PHONY: tools.lint_api
tools.lint_api:
	@echo "Executing linters on API spec"
	@spectral lint ../../docs/open-api-specs/signare-api/index_bundled_openapi.yaml --ruleset ${GIT_ROOT_DIR}/app/spectral-openapi-linter-ruleset.yaml --format pretty --fail-severity=error --verbose

.PHONY: tools.generate
tools.generate: tools.bundle_api tools.lint_api
	@echo "Generating HTTP infra"
	cd tools/http-infra-openapi-generator; $(MAKE)
	@echo "Executing go generate"
	@PATH=${PWD}/tools/bin:$$PATH go generate ./...
	@echo "Formatting go code"
	@gofmt -w -s . && goimports -w .

# Generates the docs Changelog page from the canonical root CHANGELOG.md. The
# generated copy is gitignored, so every docs build path must run this first
# (tools.start_docs depends on it); otherwise the Changelog page is dropped.
.PHONY: tools.sync_changelog
tools.sync_changelog:
	@echo "Syncing CHANGELOG into the docs site (root CHANGELOG.md is canonical)"
	@rm -f docs/mkdocs/docs/CHANGELOG.md
	@cp $(GIT_ROOT_DIR)/CHANGELOG.md docs/mkdocs/docs/CHANGELOG.md

# Verifies the vendored Swagger UI assets against the SHA-256 checksums pinned in
# their LICENSE.txt, so a tampered or accidentally-modified bundle fails the docs
# build rather than shipping silently. Bump both values below when refreshing the
# pin (see docs/mkdocs/docs/assets/js/swagger-ui-bundle.js.LICENSE.txt).
SWAGGER_ASSETS_DIR := docs/mkdocs/docs/assets
SWAGGER_JS_SHA256  := 8795ffef78de8aea8bd92d2be827f6def4f45d939330204a75c6a8d3b08cedb1
SWAGGER_CSS_SHA256 := 40170f0ee859d17f92131ba707329a88a070e4f66874d11365e9a77d232f6117

.PHONY: tools.verify_vendored
tools.verify_vendored:
	@echo "Verifying vendored Swagger UI assets against pinned SHA-256 checksums"
	@echo "$(SWAGGER_JS_SHA256)  $(SWAGGER_ASSETS_DIR)/js/swagger-ui-bundle.js" | sha256sum -c -
	@echo "$(SWAGGER_CSS_SHA256)  $(SWAGGER_ASSETS_DIR)/css/swagger-ui.css" | sha256sum -c -

.PHONY: tools.start_docs
tools.start_docs: tools.sync_changelog tools.verify_vendored
	@ docker rm -f $(SIGNARE_DOCS) || true
	@cd docs && docker build -t $(SIGNARE_DOCS) .
	@docker run -d --rm --name $(SIGNARE_DOCS) -p "8005:8000" -v $(CURDIR)/docs/mkdocs/docs:/app/docs $(SIGNARE_DOCS)
	@echo 'Hosting documentation on http://localhost:8005, refresh if needed until the documentation is build'
	@xdg-open http://localhost:8005

.PHONY: tools.stop_docs
tools.stop_docs:
	@docker rm -f $(SIGNARE_DOCS) || true
	@echo 'Closing & deleting documentation container'

.PHONY: tools.format
tools.format:
	@echo ">> Formatting"
	@goimports -w -local "github.com/lfdt-smoot" .
