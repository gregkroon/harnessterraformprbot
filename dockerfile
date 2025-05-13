FROM golang:1.21 as builder

WORKDIR /app

COPY . .

# Build without Go modules (uses GOPATH)
RUN go build -o /terraform-upgrade-bot .

FROM debian:bullseye-slim

WORKDIR /app

COPY --from=builder /terraform-upgrade-bot /terraform-upgrade-bot

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/terraform-upgrade-bot"]

