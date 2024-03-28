# Secure Env

BUILD_DIR = build
UNIT_TEST_BUILD_DIR = $(BUILD_DIR)/unit-test
UNIT_TEST_PKG = \
	./core/crypt

.PHONY: all
all:
# Run all
#
	@echo 'Nothing'

.PHONY: mock
mock:
# Run mockery
#
	@rm -rf mocks
	@mockery --all

.PHONY: unit-test
unit-test:
# Run all test cases
#
	@mkdir -p $(UNIT_TEST_BUILD_DIR)
	@go test \
		-v \
		-coverprofile=coverage.out \
		-outputdir $(UNIT_TEST_BUILD_DIR) \
		$(UNIT_TEST_PKG)

.PHONY: unit-test
unit-test-coverage: unit-test
# Run all test cases coverage
#
	@go tool cover -html=$(UNIT_TEST_BUILD_DIR)/coverage.out

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
