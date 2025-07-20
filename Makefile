APP_NAME = go-web

# Run the application
run:
	go run .

# Build a binary named $(APP_NAME)
build:
	go build -o $(APP_NAME) .

# Run all tests with verbose output
test:
	go test -v ./...

# Tidy up and download modules
tidy:
	go mod tidy

# Remove built binary and temp files
clean:
	rm -f $(APP_NAME)

# Format all Go files
fmt:
	go fmt ./...

# Install linting tool (if not installed)
lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
lint:
	golangci-lint run

# Combined target: tidy, test, build
all: tidy test build
