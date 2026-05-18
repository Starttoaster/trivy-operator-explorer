// Package mcp implements the Model Context Protocol (MCP) server for
// trivy-operator-explorer.
//
// The server is exposed over the Streamable HTTP transport on its own port
// (separate from the main UI/JSON API) so it can be routed, secured, or
// exposed independently from the rest of the application. Tools are intentionally
// generic primitives over the explorer's vulnerability and ignore-list data so
// an LLM client can compose them for ad-hoc questions.
package mcp

import (
	"fmt"
	"net/http"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/version"
)

// endpointPath is the HTTP path the streamable handler is mounted at. The
// path is conventional across MCP clients and matches the example used in
// the official Go SDK.
const endpointPath = "/mcp"

// Start runs the MCP server on the given TCP port until the underlying
// http.Server returns. The server shares the same kube client and sqlite
// connection as the main web server (initialized in cmd.Execute()).
func Start(port string) error {
	server := newServer()

	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return server
	}, nil)

	mux := http.NewServeMux()
	mux.Handle(endpointPath, handler)
	mux.Handle(endpointPath+"/", handler)

	addr := fmt.Sprintf(":%s", port)
	log.Logger.Info("MCP server listening", "addr", addr, "path", endpointPath)
	return http.ListenAndServe(addr, mux)
}

// newServer constructs the MCP server and registers every tool. It is
// extracted so tests can build a server without a network listener.
func newServer() *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "trivy-operator-explorer",
		Title:   "Trivy Operator Explorer",
		Version: version.Version,
	}, &mcpsdk.ServerOptions{
		Instructions: serverInstructions,
	})

	registerTools(server)
	return server
}

// serverInstructions is sent to clients as part of the initialize response.
// It gives an LLM enough context to choose between the available tools
// without re-discovering them from the OpenAPI spec.
const serverInstructions = `Trivy Operator Explorer MCP server.

Read-only and mutating tools for working with the vulnerability reports
produced by Aqua Security's trivy-operator in a Kubernetes cluster, plus a
persisted "ignored CVE" list.

Use the read tools (list_images, get_image, list_cves, list_images_with_cve,
list_ignored_cves) to inspect findings, then use the mutating tools
(ignore_cves, unignore_cves) to manage the ignore list per image.

Every Vulnerability returned from get_image, list_cves, and list_images_with_cve
includes the trivy classification fields "class" (e.g. "os-pkgs", "lang-pkgs")
and "package_type" (e.g. "apk", "dpkg", "gobinary", "npm"), which let you
distinguish CVEs introduced by the container base OS from those introduced by
the application's own dependencies.`
