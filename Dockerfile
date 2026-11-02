# Build the SPA, then the Go binaries, in one reproducible image.
FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
RUN apk add --no-cache gcc musl-dev git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /out/user-center ./cmd/user-center \
 && CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /out/migrate ./cmd/migrate \
 && CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /out/admin-rescue ./cmd/admin-rescue

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build /out/user-center /app/user-center
COPY --from=build /out/migrate /app/migrate
COPY --from=build /out/admin-rescue /app/admin-rescue
COPY configs /app/configs
COPY migrations /app/migrations
COPY --from=web /src/web/dist /app/web/dist
RUN mkdir -p /app/artifacts && chown -R app:app /app
USER app
ENV CONF_PATH=/app/configs/config.yaml
EXPOSE 8080 9090
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/user-center"]
