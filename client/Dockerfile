FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go .
RUN CGO_ENABLED=0 go build -o /client .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /client /client
ENTRYPOINT ["/client"]
