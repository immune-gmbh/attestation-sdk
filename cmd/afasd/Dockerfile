FROM golang:1.20

VOLUME ["/project", "/root/go", "/srv/afasd"]
WORKDIR /project
CMD ["sh", "-c", "while true; do go run ./cmd/afasd/ --log-level trace; done"]