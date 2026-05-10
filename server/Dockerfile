FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go .
RUN CGO_ENABLED=0 go build -o /server .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /server /server
ENTRYPOINT ["/server"]
