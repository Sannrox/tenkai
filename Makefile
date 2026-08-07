.DEFAULT_GOAL := test

.EXPORT_ALL_VARIABLES:
WHAT ?=

.PHONY: test validate test-integration update

# Thin workflow façade. The deterministic implementation lives in
# scripts/make-targets and the validate-*/update-* fan-out scripts.
test:
	bash scripts/make-targets/test.sh

validate:
	bash scripts/make-targets/validate.sh

test-integration:
	bash scripts/make-targets/test-integration.sh

update:
	bash scripts/make-targets/update.sh
