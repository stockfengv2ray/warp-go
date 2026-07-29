FROM golang:1.26.5 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o warp .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/warp /app/warp
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/warp
VOLUME /data
ENV STATE_FILE=/data/reg.json
EXPOSE 40000
CMD ["/app/entrypoint.sh"]
