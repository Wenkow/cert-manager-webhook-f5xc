GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)

IMAGE_NAME := ghcr.io/wenkow/cert-manager-webhook-f5xc
IMAGE_TAG := latest

ENVTEST_K8S_VERSION ?= 1.32.0

.PHONY: build
build:
	$(GO) build -trimpath -ldflags="-s -w" -o webhook .

.PHONY: test
test:
	$(GO) test -v ./f5xc/...

.PHONY: test-conformance
test-conformance: setup-envtest
	TEST_ASSET_ETCD=$(LOCALBIN)/k8s/$(ENVTEST_K8S_VERSION)-$(OS)-$(ARCH)/etcd \
	TEST_ASSET_KUBE_APISERVER=$(LOCALBIN)/k8s/$(ENVTEST_K8S_VERSION)-$(OS)-$(ARCH)/kube-apiserver \
	TEST_ASSET_KUBECTL=$(LOCALBIN)/k8s/$(ENVTEST_K8S_VERSION)-$(OS)-$(ARCH)/kubectl \
	$(GO) test -v -tags=conformance .

.PHONY: docker-build
docker-build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: docker-push
docker-push: docker-build
	docker push "$(IMAGE_NAME):$(IMAGE_TAG)"

.PHONY: deploy
deploy:
	helm install cert-manager-webhook-f5xc deploy/cert-manager-webhook-f5xc \
		--namespace cert-manager \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG)

.PHONY: undeploy
undeploy:
	helm uninstall cert-manager-webhook-f5xc --namespace cert-manager

.PHONY: clean
clean:
	chmod -R u+w $(LOCALBIN) 2>/dev/null || true
	rm -rf $(LOCALBIN) webhook

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

ENVTEST ?= $(LOCALBIN)/setup-envtest

.PHONY: setup-envtest
setup-envtest: envtest
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path

.PHONY: envtest
envtest: $(ENVTEST)
$(ENVTEST): $(LOCALBIN)
	GOBIN="$(LOCALBIN)" $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
