FROM golang:1 AS build

WORKDIR /go/src/app
COPY . .

RUN go mod download
# CGO is required for the sqlite-backed ignore list in the frontend.
RUN CGO_ENABLED=1 go build -o /go/bin/app ./cmd/frontend

FROM gcr.io/distroless/base-debian12
COPY --from=build /go/bin/app /
CMD ["/app"]
