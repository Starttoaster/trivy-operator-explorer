# API

Every HTML page has a JSON counterpart under `/api/v1/...`. Responses mirror the same view data shown in the UI, marshalled as JSON with `snake_case` keys. All read endpoints accept GET only (other methods return `405` with an `Allow` header). Missing required parameters return `400`, unknown resources return `404`, and upstream failures return `500`, each with a JSON `{"error": "..."}` body.

A machine-readable OpenAPI 3 spec is served at `/api/v1/openapi.json` and is the source of truth for parameter shapes and response schemas. It is suitable for auto-generating client SDKs or MCP tool definitions.

## Read endpoints

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/health` | Liveness probe; returns `{status, version}`. |
| GET | `/api/v1/openapi.json` | OpenAPI 3 spec describing this API. |
| GET | `/api/v1/` | Index summary (image vulnerability counts + compliance reports). |
| GET | `/api/v1/images` | Optional: `hasfix`, `showignored`, `severity`, `os_family`, `eosl`, `cve` (repeatable). |
| GET | `/api/v1/image` | Pass either `ref` (canonical fully-qualified ref, e.g. `index.docker.io/library/nginx:1.27@sha256:...`) or split `registry`/`repository`/`tag`/`digest`. Optional: `severity`, `hasfix`, `showignored`, `resources` (repeatable). |
| GET | `/api/v1/configaudits` | Optional: `namespace`, `kind`. |
| GET | `/api/v1/configaudit` | Required: `name`, `namespace`, `kind`. Optional: `severity`. |
| GET | `/api/v1/clusteraudits` | |
| GET | `/api/v1/clusteraudit` | Required: `name`, `kind`. Optional: `severity`. |
| GET | `/api/v1/clusterroles` | |
| GET | `/api/v1/clusterrole` | Required: `name`. Optional: `severity`. |
| GET | `/api/v1/exposedsecrets` | |
| GET | `/api/v1/exposedsecret` | Required: `image`, `digest`. Optional: `severity`. |
| GET | `/api/v1/roles` | Optional: `namespace`. |
| GET | `/api/v1/role` | Required: `name`, `namespace`. Optional: `severity`. |
| GET | `/api/v1/compliancereports` | |
| GET | `/api/v1/compliancereport` | Required: `id`. Optional: `severity`. Returns `404` if `id` is unknown. |

## Ignore management

CVE ignores are managed under a single endpoint. Mutations always take an array of CVE IDs (idempotent on both ends).

| Method | Path | Body | Response |
| --- | --- | --- | --- |
| GET | `/api/v1/ignores` | (none; optional `registry`, `repository`, `tag` query filters) | `[{id, registry, repository, tag, cve_id, reason}, ...]` |
| POST | `/api/v1/ignores` | `{registry, repository, tag, cve_ids: [...], reason}` | `{"inserted": N}` (already-ignored rows are skipped) |
| DELETE | `/api/v1/ignores` | `{registry, repository, tag, cve_ids: [...]}` | `{"deleted": N}` (non-existent rows are skipped) |

## Examples

```bash
curl -s 'http://localhost:8080/api/v1/health'
curl -s 'http://localhost:8080/api/v1/images?severity=critical&eosl=true' | jq '.[0]'
curl -s 'http://localhost:8080/api/v1/images?cve=CVE-2024-1234&cve=CVE-2024-5678' | jq '.[].ref'
curl -s 'http://localhost:8080/api/v1/image?ref=index.docker.io/library/nginx:1.27@sha256:abc...'
curl -s 'http://localhost:8080/api/v1/ignores?repository=library/nginx'
```
