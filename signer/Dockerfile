# SPDX-FileCopyrightText: 2026 Niki Dokovski
# SPDX-License-Identifier: Apache-2.0
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /signer .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /signer /signer
ENTRYPOINT ["/signer"]
