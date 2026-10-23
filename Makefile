# Cross-cluster mTLS demo — developer convenience targets.
# The scripts (setup.sh / clean.sh) remain the source of truth; these are
# thin, discoverable entry points plus a faster inner loop for the Go code.

MODULES := signer server client
IMAGES  := signer server client

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## go build all modules
	@for m in $(MODULES); do echo "==> build $$m"; (cd $$m && CGO_ENABLED=0 go build ./...); done

.PHONY: vet
vet: ## go vet all modules
	@for m in $(MODULES); do echo "==> vet $$m"; (cd $$m && go vet ./...); done

.PHONY: fmt
fmt: ## gofmt -l all modules (lists files needing formatting)
	@out=$$(gofmt -l $(MODULES)); if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

.PHONY: images
images: ## docker build all three images (sample-*:local)
	@for i in $(IMAGES); do echo "==> image sample-$$i:local"; docker build -t sample-$$i:local ./$$i; done

.PHONY: lint
lint: ## shellcheck all scripts + gofmt check
	shellcheck setup.sh clean.sh server/setup.sh client/setup.sh
	@$(MAKE) --no-print-directory fmt

.PHONY: check
check: build vet lint ## build + vet + lint (the CI gate)

.PHONY: up
up: ## Full end-to-end: clusters, CAs, images, deploy, verify
	./setup.sh

.PHONY: down
down: ## Delete both kind clusters and generated certs
	./clean.sh
