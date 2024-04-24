# Secure Env

BUILD_DIR = build
TEST =
UNIT_TEST_BUILD_DIR = $(BUILD_DIR)/unit-test
UNIT_TEST_PKG = \
	./core/crypto \
	./core/crypto/impl \
	./core/env \
	./core/env/impl

INTEGRATION_TEST_PKG = \
	./core/crypto/test \

MOCK_DIR = \
	./core/crypto/mock

.PHONY: all
all:
# Run all
#
	@echo 'Nothing'

.PHONY: mock
mock:
# Run mockery
#
	@rm -rf $(MOCK_DIR)
	@mockery

.PHONY: unit-test
unit-test:
# Run all test cases
#
	@mkdir -p $(UNIT_TEST_BUILD_DIR)
	@go clean -testcache
	@go test \
		-v \
		-coverprofile=coverage.out \
		-outputdir $(UNIT_TEST_BUILD_DIR) \
		-run '$(TEST)' \
		$(UNIT_TEST_PKG)

.PHONY: unit-test
unit-test-coverage:
# Run all test cases coverage
#
	@go tool cover -html=$(UNIT_TEST_BUILD_DIR)/coverage.out

.PHONY: integration-test
integration-test:
# Run all test cases
#
	@go clean -testcache
	@go test \
		-v \
		-run '$(TEST)' \
		$(INTEGRATION_TEST_PKG)

.PHONY: build
build:
# Build CLI binary
#
	@go build -C cli -o ../build/senv

.PHONY: clean
clean:
# Remove build
#
	@rm -rf build
