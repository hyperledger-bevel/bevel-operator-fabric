# Current Operator version
VERSION ?= 0.0.1
# Default bundle image tag
BUNDLE_IMG ?= controller-bundle:$(VERSION)
# Options for 'bundle-build'
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:maxDescLen=0,generateEmbeddedObjectMeta=true"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOFMT=gofmt

# Tool versions
GOLANGCI_LINT_VERSION ?= v1.61.0
CONTROLLER_GEN_VERSION ?= v0.16.4

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[0;33m
NC=\033[0m # No Color

.PHONY: all
all: manager

##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: api-reference
api-reference: ## Generate API reference documentation
	refdocs \
		-api-dir ./api/hlf.kungfusoftware.es/v1alpha1 \
		-template-dir ./docs/api/autogen/templates \
		-config ./docs/api/autogen/config.json \
		-out-file ./docs/api/hlf.kungfusoftware.io.ref.md
	mv ./docs/api/hlf.kungfusoftware.io.ref.md ./website-docs/docs/api-reference.md

.PHONY: generate
generate: controller-gen ## Generate code (DeepCopy, etc.)
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: fmt
fmt: ## Run go fmt against code
	$(GOFMT) -s -w .

.PHONY: vet
vet: ## Run go vet against code
	$(GOVET) ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run --timeout=10m

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and fix issues
	$(GOLANGCI_LINT) run --fix --timeout=10m

##@ Testing

.PHONY: test
test: generate fmt vet manifests ## Run tests
	$(GOTEST) ./controllers/... -timeout 20m -coverprofile cover.out

.PHONY: test-coverage
test-coverage: generate fmt vet manifests ## Run tests with coverage report
	$(GOTEST) ./controllers/... -timeout 20m -coverprofile cover.out -covermode=atomic
	$(GOCMD) tool cover -html=cover.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

.PHONY: test-coverage-report
test-coverage-report: ## Display coverage summary
	@$(GOCMD) tool cover -func=cover.out | tail -1

.PHONY: test-short
test-short: ## Run short tests only (skip integration tests)
	$(GOTEST) ./controllers/... -short -timeout 5m

.PHONY: test-verbose
test-verbose: generate fmt vet manifests ## Run tests with verbose output
	$(GOTEST) ./controllers/... -v -timeout 20m -coverprofile cover.out

##@ Build

.PHONY: manager
manager: generate fmt vet ## Build manager binary
	$(GOBUILD) -o bin/manager main.go

.PHONY: run
run: generate fmt vet manifests ## Run a controller from your host
	$(GOCMD) run ./main.go

.PHONY: kubectl-plugin
kubectl-plugin: ## Build kubectl-hlf plugin
	cd kubectl-hlf && $(GOBUILD) -o kubectl-hlf main.go
	sudo mv kubectl-hlf/kubectl-hlf /usr/local/bin/kubectl-hlf

.PHONY: docker-build
docker-build: ## Build docker image
	docker build . -t ${IMG}

.PHONY: docker-push
docker-push: ## Push docker image
	docker push ${IMG}

##@ Deployment

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config
	$(KUSTOMIZE) build config/default | kubectl delete -f -

##@ Bundle

.PHONY: bundle
bundle: manifests ## Generate bundle manifests and metadata, then validate generated files
	operator-sdk generate kustomize manifests -q
	kustomize build config/manifests | operator-sdk generate bundle -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)
	operator-sdk bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

##@ Security

.PHONY: security-scan
security-scan: ## Run security scan with trivy
	@command -v trivy >/dev/null 2>&1 || { echo "$(RED)trivy is not installed. Install it from https://trivy.dev$(NC)"; exit 1; }
	trivy fs --config trivy.yaml .

.PHONY: gosec
gosec: ## Run gosec security scanner
	@command -v gosec >/dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -exclude-dir=internal -exclude-dir=pkg/client ./...

##@ Quality

.PHONY: check
check: fmt vet lint test ## Run all checks (fmt, vet, lint, test)
	@echo "$(GREEN)All checks passed!$(NC)"

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks
	@command -v pre-commit >/dev/null 2>&1 || { echo "$(RED)pre-commit is not installed. Install it with: pip install pre-commit$(NC)"; exit 1; }
	pre-commit run --all-files

.PHONY: pre-commit-install
pre-commit-install: ## Install pre-commit hooks
	@command -v pre-commit >/dev/null 2>&1 || { echo "$(RED)pre-commit is not installed. Install it with: pip install pre-commit$(NC)"; exit 1; }
	pre-commit install

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GOCMD) mod tidy

.PHONY: verify
verify: tidy generate manifests ## Verify generated files are up to date
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "$(RED)Generated files are not up to date. Please run 'make generate manifests' and commit the changes.$(NC)"; \
		git status --porcelain; \
		exit 1; \
	fi
	@echo "$(GREEN)Generated files are up to date!$(NC)"

##@ Tools

# Find or download controller-gen
CONTROLLER_GEN = $(GOBIN)/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION) ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

KUSTOMIZE = $(GOBIN)/kustomize
.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary
ifeq (, $(shell which kustomize))
	@{ \
	set -e ;\
	KUSTOMIZE_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$KUSTOMIZE_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go install sigs.k8s.io/kustomize/kustomize/v5@latest ;\
	rm -rf $$KUSTOMIZE_GEN_TMP_DIR ;\
	}
KUSTOMIZE=$(GOBIN)/kustomize
else
KUSTOMIZE=$(shell which kustomize)
endif

GOLANGCI_LINT = $(GOBIN)/golangci-lint
.PHONY: golangci-lint
golangci-lint: ## Download golangci-lint locally if necessary
ifeq (, $(shell which golangci-lint))
	@{ \
	set -e ;\
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) $(GOLANGCI_LINT_VERSION) ;\
	}
GOLANGCI_LINT=$(GOBIN)/golangci-lint
else
GOLANGCI_LINT=$(shell which golangci-lint)
endif

##@ Cleanup

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -f cover.out coverage.html
	rm -rf kubectl-hlf/kubectl-hlf
