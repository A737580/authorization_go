FROM golang:1.24-alpine AS builder 

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service-go .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/auth-service-go ./auth-service-go

COPY --from=builder /app/migrations ./migrations

EXPOSE 8080

CMD ["/app/auth-service-go"]