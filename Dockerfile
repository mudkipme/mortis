# Build stage
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o mortis .

# Final stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/mortis .
EXPOSE 5431
CMD ["./mortis"]