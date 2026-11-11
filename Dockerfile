FROM golang:1 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /bugscan ./cmd/bugscan

FROM gcr.io/distroless/static
COPY --from=build /bugscan /bugscan
ENTRYPOINT ["/bugscan"]
