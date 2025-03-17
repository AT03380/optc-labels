.PHONY: all build fmt

all: fmt build

fmt:
	go fmt
	go fmt matcher/matcher.go

build:
	go build -o build/
	go build -o build/ matcher/matcher.go
