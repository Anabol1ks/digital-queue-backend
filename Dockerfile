# 1) Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /app
# кешируем модули
COPY go.mod go.sum ./
RUN go mod download

# копируем всё и собираем
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server main.go

# 2) Final stage
FROM alpine:latest
WORKDIR /app
# для HTTPS/DB‑сертификатов
RUN apk add --no-cache ca-certificates

# копируем бинарь и документацию (swagger.json/yaml)
COPY --from=builder /app/server .
COPY --from=builder /app/docs ./docs

# пример .env (будет переопределён из docker-compose)
COPY .env.docker .env

EXPOSE 8080
CMD ["./server"]
