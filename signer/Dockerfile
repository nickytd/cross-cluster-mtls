FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /signer .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /signer /signer
ENTRYPOINT ["/signer"]
