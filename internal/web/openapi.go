package web

import (
	_ "embed" // embed for the openapi spec
	"net/http"
)

//go:embed openapi.json
var openapiSpec []byte

// apiOpenAPIHandler serves the embedded OpenAPI 3 spec describing the /api/v1
// surface, allowing API consumers (e.g. an MCP server) to derive tool schemas
// directly from the running server.
func apiOpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(openapiSpec)
}
