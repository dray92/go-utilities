
TEST_ARGS ?= 
COVERAGE_FILE="coverage.out"

test:
	go test ./... $(TEST_ARGS)

cover:
	TEST_ARGS="-coverprofile $(COVERAGE_FILE)" $(MAKE) test
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html
