default: test

build:
    go build -o mcp-firewall ./cmd/mcp-firewall

test:
    go test ./...

lint:
    go vet ./...

run config="config.yaml": build
    ./mcp-firewall -config {{config}}

echoserver:
    go build -o testdata/echoserver/echoserver ./testdata/echoserver
