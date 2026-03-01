FROM golang:1 AS build

WORKDIR /go/src/app
COPY . .

RUN go mod download

# BINARY can be: frontend (default), agent, or api
# frontend is built from the root module (.), agent and api from cmd/<name>
ARG BINARY=frontend

RUN if [ "$BINARY" = "frontend" ]; then \
      CGO_ENABLED=0 go build -o /go/bin/app .; \
    else \
      CGO_ENABLED=0 go build -o /go/bin/app ./cmd/${BINARY}; \
    fi

FROM gcr.io/distroless/static-debian12
COPY --from=build /go/bin/app /
CMD ["/app"]
