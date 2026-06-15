.PHONY: build test lint run clean openapi

BINARY_NAME=kratos-webhooks
IMAGE_NAME=alkemio/kratos-webhooks
VERSION=v0.0.1
BUILD_DIR=./bin

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

run:
	go run ./cmd/server

clean:
	rm -rf $(BUILD_DIR)
	go clean

tidy:
	go mod tidy

openapi:
	apispec --dir . --output openapi.yaml --config apispec.yaml --skip-cgo

docker-build:
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-run:
	docker run -p 8080:8080 --env-file .env $(IMAGE_NAME):$(VERSION)
