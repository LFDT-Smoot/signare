SHELL=/bin/bash -o pipefail

GIT_ROOT_DIR:=$(shell git rev-parse --show-toplevel)

OPENAPI_GENERATOR_POM_VERSION := $(shell cd $(GIT_ROOT_DIR)/app/tools/http-infra-openapi-generator/signare-plugin && mvn help:evaluate -Dexpression=openapi-generator-version -q -DforceStdout)

# openapi-generator-cli is fetched on demand from Maven Central and verified against a pinned
# SHA-256 (openapi-generator-cli-<version>.jar.sha256), instead of being committed as a 30MB binary blob.
OPENAPI_GENERATOR_DIR := $(GIT_ROOT_DIR)/app/tools/http-infra-openapi-generator
OPENAPI_GENERATOR_CACHE := $(OPENAPI_GENERATOR_DIR)/.cache
OPENAPI_GENERATOR_JAR := $(OPENAPI_GENERATOR_CACHE)/openapi-generator-cli-$(OPENAPI_GENERATOR_POM_VERSION).jar
OPENAPI_GENERATOR_URL := https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/$(OPENAPI_GENERATOR_POM_VERSION)/openapi-generator-cli-$(OPENAPI_GENERATOR_POM_VERSION).jar
OPENAPI_GENERATOR_SHA256_FILE := $(OPENAPI_GENERATOR_DIR)/openapi-generator-cli-$(OPENAPI_GENERATOR_POM_VERSION).jar.sha256

API_SPEC_ROOT ?= "$(GIT_ROOT_DIR)/app/docs/open-api-specs/signare-api"
API_SPEC_BUNDLE ?= "$(GIT_ROOT_DIR)/app/docs/open-api-specs/signare-api/index_bundled_openapi.yaml"
API_INFRA_GENERATED_OUT ?= "$(GIT_ROOT_DIR)/app/pkg/infra/generated"

.PHONY: default
default: build_signare_plugin generate_signare_http_infra

.PHONY: build_signare_plugin
build_signare_plugin:
	@cd $(GIT_ROOT_DIR)/app/tools/http-infra-openapi-generator/signare-plugin; mvn package

.PHONY: generate_signare_http_infra
generate_signare_http_infra: generate_http_infra format_go_code format_files

.PHONY: fetch_openapi_generator
fetch_openapi_generator:
	@if [ ! -f "$(OPENAPI_GENERATOR_SHA256_FILE)" ]; then \
		echo "ERROR: missing pinned checksum $(OPENAPI_GENERATOR_SHA256_FILE); commit the .sha256 for openapi-generator $(OPENAPI_GENERATOR_POM_VERSION)." >&2; \
		exit 1; \
	fi
	@mkdir -p $(OPENAPI_GENERATOR_CACHE)
	@if [ ! -f "$(OPENAPI_GENERATOR_JAR)" ]; then \
		echo "Downloading openapi-generator-cli $(OPENAPI_GENERATOR_POM_VERSION) from Maven Central"; \
		tmp="$$(mktemp "$(OPENAPI_GENERATOR_JAR).XXXXXX")"; \
		curl -fsSL --remove-on-error "$(OPENAPI_GENERATOR_URL)" -o "$$tmp" || { rm -f "$$tmp"; echo "ERROR: failed to download $(OPENAPI_GENERATOR_URL)" >&2; exit 1; }; \
		mv "$$tmp" "$(OPENAPI_GENERATOR_JAR)"; \
	fi
	@if command -v sha256sum >/dev/null 2>&1; then shacmd="sha256sum"; \
	elif command -v shasum >/dev/null 2>&1; then shacmd="shasum -a 256"; \
	else echo "ERROR: need 'sha256sum' or 'shasum' to verify $(OPENAPI_GENERATOR_JAR)" >&2; exit 1; fi; \
	if ! echo "$$(cat $(OPENAPI_GENERATOR_SHA256_FILE))  $(OPENAPI_GENERATOR_JAR)" | $$shacmd -c - >/dev/null 2>&1; then \
		echo "ERROR: openapi-generator-cli $(OPENAPI_GENERATOR_POM_VERSION) checksum mismatch for $(OPENAPI_GENERATOR_JAR) (expected $$(cat $(OPENAPI_GENERATOR_SHA256_FILE)))." >&2; \
		echo "Removing it so the next run re-downloads." >&2; \
		rm -f "$(OPENAPI_GENERATOR_JAR)"; \
		exit 1; \
	fi; \
	echo "openapi-generator-cli $(OPENAPI_GENERATOR_POM_VERSION) checksum OK"

.PHONY: generate_http_infra
generate_http_infra: fetch_openapi_generator
	- @rm -rf $(API_INFRA_GENERATED_OUT)
	@GO_POST_PROCESS_FILE="/usr/local/go/bin/gofmt -w" java -cp $(OPENAPI_GENERATOR_JAR):$(OPENAPI_GENERATOR_DIR)/signare-plugin/target/signare-plugin-1.0.0.jar org.openapitools.codegen.OpenAPIGenerator generate -g signare-http-infra -i $(API_SPEC_BUNDLE) --enable-post-process-file --package-name httpinfra --model-package httpinfra --api-package httpinfra --additional-properties=useOneOfDiscriminatorLookup=true,generatedActionsFilePath=$(GIT_ROOT_DIR)/app/include/rbac/actions-generated.yaml -o $(API_INFRA_GENERATED_OUT)

.PHONY: openapi_generator_version
openapi_generator_version:
	@echo $(OPENAPI_GENERATOR_POM_VERSION)

format_go_code:
	gofmt -w -s $(GIT_ROOT_DIR)/app && goimports -w $(GIT_ROOT_DIR)/app

# format_files is needed in order to align the generated code with the current lint configuration
format_files:
	find $(GIT_ROOT_DIR)/app/pkg/infra -type f -name "*.go" -exec sed -i 's/Ip/IP/g' {} \;
	find $(GIT_ROOT_DIR)/app/pkg/infra -type f -name "*.go" -exec sed -i 's/Tls/TLS/g' {} \;
	find $(GIT_ROOT_DIR)/app/pkg/infra -type f -name "*.go" -exec sed -i 's/\([^"]\)Url\([^"]\)/\1URL\2/g' {} \;
	find $(GIT_ROOT_DIR)/app/pkg/infra -type f -name "*.go" -exec sed -i 's/Api/API/g' {} \;
	find $(GIT_ROOT_DIR)/app/pkg/infra -type f -name "*.go" -exec sed -i 's/Http/HTTP/g' {} \;
