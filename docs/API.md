# API

Every HTML page has a JSON counterpart under `/api/v1/...`. Responses mirror the same view data shown in the UI, marshalled as JSON with `snake_case` keys. All endpoints accept the same query parameters as the HTML routes; missing required parameters return `400`, unknown resources return `404`, and upstream failures return `500`, each with a JSON `{"error": "..."}` body.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/` | Index summary (image vulnerability counts + compliance reports). |
| GET | `/api/v1/images` | Optional: `hasfix`, `showignored`. |
| GET | `/api/v1/image` | Required: `repository`, `digest`. Optional: `registry`, `tag`, `severity`, `resources`, `hasfix`, `showignored`. |
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
| GET | `/api/v1/compliancereport` | Required: `id`. Optional: `severity`. |

Example:

```bash
curl -s 'http://localhost:8080/api/v1/images?hasfix=true' | jq '.[0]'
```
