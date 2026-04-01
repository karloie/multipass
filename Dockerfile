# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=v0.0.1
ARG COMMIT=unknown
ARG GO_BUILD_TAGS=
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags "${GO_BUILD_TAGS}" \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /multipass \
    ./cmd/multipass

# Runtime stage
FROM alpine:3.22

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /multipass /app/multipass

# Non-root user
RUN adduser -D -u 1000 multipass && \
    chown -R multipass:multipass /app
USER multipass

EXPOSE 8080

ENTRYPOINT ["/app/multipass"]
CMD ["/etc/multipass/config.yaml"]
