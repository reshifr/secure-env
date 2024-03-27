# Secure Env

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

.PHONY: test
test:
# Run all test cases
#
	@go test -v \
		./core/crypt

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
