# syntax=docker/dockerfile:1
# OpenPak xbl: the modern Xbox network services for XAL/XSAPI titles.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" -o /out/xbld ./cmd/xbld

FROM gcr.io/distroless/static
COPY --from=build /out/xbld /xbld
USER nonroot:nonroot
EXPOSE 23500 23501 23502
HEALTHCHECK CMD ["/xbld", "healthcheck"]
ENTRYPOINT ["/xbld"]
