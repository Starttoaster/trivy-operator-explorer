# Contributing

## Local dev

Making changes to the HTML may require [TailwindCSS](https://tailwindcss.com/blog/standalone-cli) to be installed. Specifically this project uses TailwindCSS v3, and the CLI for that can be found [in their release page](https://github.com/tailwindlabs/tailwindcss/releases/tag/v3.4.17).

Assuming the standalone TailwindCSS utility is installed, you can build and run this project locally with:

```bash
go generate && \
go build && \
./trivy-operator-explorer --kubeconfig="$HOME/.kube/config"
```

If you don't make changes to any HTML templates, you don't need to run `go generate` and don't need the TailwindCSS standalone CLI utility installed.

When running, you can view the dashboard in your browser at `<ip>:8080`

## Pull Requests

Please leave a short thoughtful message about your change and copy in a screenshot of how the change looks in dark and light mode if you make a change to the HTML templates. The dark/light theme is often set in browser settings, unless the browser is set to respect the OS theme.
