SHELL=/bin/bash -o pipefail

SIGNARE_DIR=$(shell cd ../..; pwd)

.PHONY: tools.run_default
tools.run_default:
	@go run ./cmd/rbac_validator.go \
	  --openapiSpecFiles $(SIGNARE_DIR)/docs/open-api-specs/signare-api/index_bundled_openapi.yaml \
      --rolesFilePath $(SIGNARE_DIR)/include/rbac/roles.yaml \
      --permissionsFilePath $(SIGNARE_DIR)/include/rbac/permissions.yaml \
      --actionsFilesPath $(SIGNARE_DIR)/include/rbac/actions-generated.yaml,$(SIGNARE_DIR)/include/rbac/actions-manual.yaml \
      --operationIdInclusionsFilePath $(SIGNARE_DIR)/include/rbac/actions-manual.yaml

.PHONY: tools.help
tools.help:
	@go run ./cmd/rbac_validator.go --help

# This module is outside the app module, so app's unit_test does not reach it on its own. It delegates
# here instead, which is also what a pipeline should call.
.PHONY: unit_test
unit_test:
	@echo "Executing tests for the rbac-validator tool"
	@go test ./...
