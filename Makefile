.PHONY: build test fuzz lint demo

build:
	go build -trimpath -o dpdpward ./cmd/dpdpward

test:
	go test -race ./...

fuzz:
	go test -run '^$$' -fuzz=FuzzParsers -fuzztime=60s ./internal/extract/
	go test -run '^$$' -fuzz=FuzzParseFile -fuzztime=60s ./internal/iac/

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

demo: build
	./dpdpward scan --dir examples/demo-app
	./dpdpward ropa --dir examples/demo-app
	./dpdpward breach --aware 2027-06-01T10:30:00+05:30 --dir examples/demo-app
