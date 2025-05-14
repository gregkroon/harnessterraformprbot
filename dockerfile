FROM golang:1.24.1 AS builder

WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o terraform-upgrade-bot .

FROM alpine:latest

RUN apk --no-cache add ca-certificates bash

WORKDIR /app
COPY --from=builder /app/terraform-upgrade-bot /terraform-upgrade-bot

ENTRYPOINT ["/terraform-upgrade-bot"]

