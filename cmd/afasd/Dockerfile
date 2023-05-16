FROM golang:1.20

VOLUME ["/project", "/root/go"]
WORKDIR /project
CMD ["sh", "-c", "while true; do go run ./cmd/afasd/ --log-level trace; done"]