# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG TARGETARCH
ARG VERSION=dev
RUN go mod download \
  && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X openvpn-control-agent/internal.AgentVersion=${VERSION}" \
    -o /out/agent ./cmd/agent

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /out/agent /usr/local/bin/openvpn-control-agent
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/openvpn-control-agent"]
