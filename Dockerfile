FROM golang:1.26.5 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o warp .

FROM gcr.io/distroless/static-debian12:latest
WORKDIR /app
COPY --from=builder /app/warp /app/warp
VOLUME /data
ENV STATE_FILE=/data/reg.json
EXPOSE 40000
CMD ["/app/warp", "-l", "0.0.0.0:40000", "-user", "stockfeng", "-pass", "forex_811714"]
