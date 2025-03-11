.PHONY: build run test lint generate migrate clean

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GORUN=$(GOCMD) run
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=frank
MAIN_PATH=./cmd/server

all: generate test lint build

build:
	$(GOBUILD) -o ./bin/$(BINARY_NAME) $(MAIN_PATH)

run:
	$(GORUN) $(MAIN_PATH)

test:
	$(GOTEST) -v ./...

lint:
	golangci-lint run

generate:
	go run -mod=mod entgo.io/ent/cmd/ent generate ./ent/schema

migrate:
	./scripts/migrate.sh

clean:
	rm -f ./bin/$(BINARY_NAME)

deps:
	$(GOGET) -u ./...
