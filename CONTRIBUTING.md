# Contributing

## Local dev

Making changes to the HTML may require [TailwindCSS](https://tailwindcss.com/blog/standalone-cli) to be installed. Specifically this project uses TailwindCSS v3, and the CLI for that can be found [in their release page](https://github.com/tailwindlabs/tailwindcss/releases/tag/v3.4.17).

This project is split into two binaries under `cmd/`:

- `cmd/collector` reads trivy-operator reports from a cluster and writes them to an S3 bucket.
- `cmd/frontend` reads those report bundles from S3 and serves the web UI, JSON API, and MCP server.

Assuming the standalone TailwindCSS utility is installed, you can build and run them locally with:

```bash
# Regenerate CSS if you changed HTML templates (needs the TailwindCSS standalone CLI).
go generate ./...

# Collector: read from your cluster and write to a bucket.
go build -o collector ./cmd/collector && \
./collector --kubeconfig="$HOME/.kube/config" \
  --cluster-name=local --s3-bucket=my-bucket --s3-region=us-east-1

# Frontend: read from the bucket and serve the UI on :8080.
go build -o frontend ./cmd/frontend && \
./frontend --s3-bucket=my-bucket --s3-region=us-east-1
```

Both binaries use the standard AWS credential chain (env vars, shared config, IRSA). For local runs, export `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and optionally `AWS_REGION`) or use an `AWS_PROFILE`.

If you don't make changes to any HTML templates, you don't need to run `go generate` and don't need the TailwindCSS standalone CLI utility installed.

When running the frontend, you can view the dashboard in your browser at `<ip>:8080`

## Pull Requests

Please leave a short thoughtful message about your change and copy in a screenshot of how the change looks in dark and light mode if you make a change to the HTML templates. The dark/light theme is often set in browser settings, unless the browser is set to respect the OS theme.
