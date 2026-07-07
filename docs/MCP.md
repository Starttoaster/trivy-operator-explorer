# MCP server

The trivy-operator-explorer **frontend** ships a built-in [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that exposes the vulnerability and ignore-list data as a small set of generic, composable tools. The server runs in the same process as the UI/JSON API but listens on its own port, so it can be routed, secured, or firewalled separately from the rest of the application. Its data comes from the report bundles that collectors write to S3 (see [the README](../README.md)), not directly from a Kubernetes cluster.

### Multi-cluster scoping

Every read tool (`list_images`, `get_image`, `list_cves`, `list_images_with_cve`) accepts an optional `cluster` input. Set it to a cluster name to scope results to that cluster, or omit it to aggregate across all clusters in the bucket. The ignore-list tools are global (not cluster-scoped), matching the sqlite schema.

The tools are intentionally primitives (`list_clusters`, `list_images`, `get_image`, `list_cves`, `list_images_with_cve`, `list_ignored_cves`, `ignore_cves`, `unignore_cves`) rather than task-specific helpers. An LLM client composes them to answer ad-hoc questions; worked examples are at the bottom of this page.

## Configuration

The server is enabled by default and uses the [Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http) at the path `/mcp`.

| Flag | Env var | Default | Notes |
| --- | --- | --- | --- |
| `--mcp-port` | `TRIVY_OPERATOR_EXPLORER_MCP_PORT` | `8081` | TCP port for the MCP listener. |

The UI/JSON API still listens on `--server-port` (default `8080`). The MCP server shares the same S3-backed report cache and sqlite ignore-list connection, so any change made via `ignore_cves` is immediately visible in the UI and at `/api/v1/ignores`.

When deployed via the Helm chart in [chart/trivy-operator-explorer](../chart/trivy-operator-explorer), the chart's `Service` exposes both ports (`http` and `mcp`). Override `config.mcp_port` and `service.mcpPort` together to change the MCP port. There is no authentication on the MCP endpoint, so treat it the same way you treat the JSON API and rely on network policy / ingress auth to gate access.

## Connecting a client

Any MCP-aware client that speaks Streamable HTTP will work. The endpoint URL is `http://<host>:<mcp_port>/mcp`. Example configurations:

### Claude Desktop / `mcp.json`

```json
{
  "mcpServers": {
    "trivy-operator-explorer": {
      "url": "http://localhost:8081/mcp",
      "transport": "streamable-http"
    }
  }
}
```

### Manual probe with curl

The server speaks JSON-RPC 2.0 over HTTP. A minimal `initialize` round-trip:

```bash
curl -sS -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  http://localhost:8081/mcp
```

## Tool reference

Each tool's full input/output JSON Schema is published over the MCP `tools/list` method. The summary below is the same `description` field returned in that listing.

### `list_clusters` (read)

List the cluster names whose trivy-operator reports are currently available. Call this first in a multi-cluster deployment, then pass a returned name as the optional `cluster` argument on the other read tools to scope results to that cluster (omit it to aggregate across all clusters). Takes no inputs; returns `{total, clusters}`.

### `list_images` (read)

List every container image known to the cluster (scanned by trivy-operator plus any unscanned images detected via running pods). Returns per-image summary with vulnerability counts grouped by severity, fix-available counts, OS metadata, and the workloads that use the image. Mirrors the filters available at `/api/v1/images`.

Each entry in `critical_vulnerabilities` / `high_vulnerabilities` / `medium_vulnerabilities` / `low_vulnerabilities` carries Trivy's classification fields (`class`, `package_type`, `pkg_path`, `pkg_purl`) — same definitions as for `get_image` below — so a single `list_images` call is enough to triage "base-OS CVE vs. application CVE" without falling back to `list_cves`.

Inputs (all optional): `cluster`, `severity`, `has_fix`, `show_ignored`, `os_family`, `eosl` (tri-state), `cve_ids` (logical AND).

### `get_image` (read)

Full vulnerability list for a single image. Identify the image either by `ref` (canonical fully-qualified ref like `index.docker.io/library/nginx:1.27@sha256:...`) or by split `registry`/`repository`/`tag`/`digest`. Each returned `Vulnerability` includes Trivy's classification fields:

- `class` — typically `"os-pkgs"` for OS-distribution packages or `"lang-pkgs"` for application packages.
- `package_type` — the specific package manager (`apk`, `dpkg`, `rpm`, `gobinary`, `node-pkg`, `python-pkg`, ...).
- `pkg_path`, `pkg_purl` — package location and PURL identifier when known.

These let an LLM distinguish CVEs introduced by the container base OS from those introduced by the application's own dependencies, without the server having to bake in a heuristic.

When the upstream trivy scanner leaves `class` / `package_type` blank but still emits a `pkg_purl`, the explorer derives them from the purl's type prefix (`pkg:apk/...` → `os-pkgs`/`apk`, `pkg:npm/...` → `lang-pkgs`/`node-pkg`, `pkg:pypi/...` → `lang-pkgs`/`python-pkg`, …). This means clients can rely on the two fields being populated for every vulnerability whose purl carries a recognized type, regardless of trivy-operator version.

Inputs: `ref` OR (`repository` + `digest`, with optional `registry` + `tag`). Optional filters: `cluster`, `severity`, `has_fix`, `show_ignored`, `resources`.

### `list_cves` (read)

Cluster-wide CVE rollup. For every unique CVE that appears in any vulnerability report, returns the worst severity, max CVSS score, fix availability, Trivy class/package type, count of affected images, and (per-affected-image) the vulnerable/fixed version, package path, and ignore state.

Top-level `class` and `package_type` on each CVE aggregate are populated using the same purl-fallback as `get_image` / `list_images`, so `list_cves(class="os-pkgs")` and `list_cves(package_type="apk")` filter server-side instead of forcing the client to download every CVE and parse `affected_images[].pkg_purl`. Affected-image entries carry the same fields.

Inputs (all optional): `cluster`, `severity`, `has_fix` (tri-state), `class`, `package_type`, `cve_id` (single-CVE lookup), `show_ignored`, `sort_by`, `limit`.

`sort_by` values:

- `pressure_desc` (default) — `max_score * affected_image_count`. A rough proxy for "worth my time today".
- `score_desc` — by CVSS score, highest first.
- `affected_count_desc` — by image footprint, highest first.
- `cve_id_asc` — lexicographic.

### `list_images_with_cve` (read)

Look up a single CVE by ID and return the per-image affected list. Inputs: `cve_id` (required), `cluster` (optional), `severity` (optional defensive filter), `show_ignored`. Returns `{found, cve}`.

### `list_ignored_cves` (read)

List all (image, CVE) pairs currently in the persisted ignore list. Inputs (all optional): `registry`, `repository`, `tag`.

### `ignore_cves` (mutation)

Mark one or more CVEs as ignored for a specific image. Idempotent: rows that already exist are skipped and the response only counts newly inserted rows. A non-empty `reason` is required so the ignore list stays auditable.

Inputs: `ref` OR (`repository` + `tag`, with optional `registry`), `cve_ids` (required), `reason` (required). Returns `{registry, repository, tag, inserted}`.

### `unignore_cves` (mutation)

Remove one or more ignored-CVE rows for a specific image. Idempotent: missing rows are silently skipped.

Inputs: `ref` OR (`repository` + `tag`, with optional `registry`), `cve_ids` (required). Returns `{registry, repository, tag, deleted}`.

## Worked examples

The three workflows below are how a typical LLM-client conversation would compose the primitives. They are not separate tools.

### "Which images have critical, fixable CVEs that are unlikely to come from the base OS?"

```text
1. Call list_cves(severity="critical", has_fix=true, class="lang-pkgs")
2. Read affected_images[].ref off each returned aggregate to get the image list.
```

`class="lang-pkgs"` is Trivy's own classification for application/language packages (Go binaries, npm, pypi, ...), which is the same heuristic Trivy itself uses to separate OS-distro CVEs from app CVEs. Drop the `class` filter if you want to inspect every critical fixable CVE and decide per-finding.

### "Ignore every CVE that's likely introduced by the base OS"

```text
1. Call list_cves(class="os-pkgs", show_ignored=false) to enumerate the candidates.
   (You may want to also filter by has_fix=false, since fixable base-OS CVEs are
   often worth bumping the base image for.)
2. For each affected image, call ignore_cves(ref=..., cve_ids=[...],
   reason="base OS CVE, not in code execution path").
```

The mutation is split per-image because the persisted ignore list is keyed on `(registry, repository, tag, cve_id)`. The LLM gets to choose the `reason` text and is expected to confirm with the user before sending the batch of `ignore_cves` calls.

### "What are the top 10 most pressing CVEs in my cluster?"

```text
1. Call list_cves(sort_by="pressure_desc", limit=10).
```

`pressure_desc` ranks by `max_score * affected_image_count`, which biases the top of the list toward CVEs that are both severe and widespread. Swap in `score_desc` for "pure severity" or `affected_count_desc` for "pure blast radius".
