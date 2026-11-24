# InABox Games — Forager isolation test

This repository is an isolated test deployment. It does not replace or modify the live InABox Games site.

## Cloudflare Worker setup

Connect this repository to Cloudflare Workers using the Git integration.

- Repository: `FablesEnd1/InABox-Games-Forager-Test`
- Production branch: `main`
- Root directory: leave blank (repository root)
- Build command: leave blank
- Deploy command: `npx wrangler deploy`

The Worker configuration is in `wrangler.toml`. It already points its server-side API proxy at the new test Apps Script deployment.

After Cloudflare deploys, open the Worker URL and test the gallery, game modal, and Forager. Do not change the production GitHub repository or production Apps Script deployment.

## Apps Script

`AppsScript-Code.gs` is the matching test Apps Script source. It preserves the existing site functions and adds the API dispatcher used by the Worker. The deployed test Apps Script URL is configured in `wrangler.toml`; it is not exposed in the browser page.

If you make further changes to the Apps Script code, paste the complete file into the separate test Apps Script project and deploy a new version there.