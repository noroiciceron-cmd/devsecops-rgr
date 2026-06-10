# Этап 1: сборка приложения
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /server .

# Этап 2: минимальный финальный образ
FROM scratch

COPY --from=builder /server /server

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/server"]
