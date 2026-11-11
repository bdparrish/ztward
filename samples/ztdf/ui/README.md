# ZTDF Viewer

A browser app that opens Zero Trust Data Format (`.ztdf`) files. Sign in, drop a `.ztdf` file
onto the page, and the viewer asks Ztward's Key Access service for the file's key. If your
attributes satisfy the file's policy, the file is decrypted and shown in the browser; if not,
you see why access was denied.

The file is decrypted entirely in the browser with the Web Crypto API, using the
[`@ztward/sdk`](../../../sdk/js) JavaScript SDK. The plaintext never leaves your machine.

## What it demonstrates

- **Policy enforced at open time:** whether a file opens is decided when you open it, not when it
  was shared, so access can be changed or revoked after the file has been sent.
- **Per-user client keys:** on first use the viewer generates a key pair for you, keeps the private
  key non-extractable in the browser, and registers the public key with the Key Manager. Keys
  expire after 24 hours by default (`VITE_CLIENT_KEY_EXPIRATION_MS`).
- **Sign-in with OIDC:** authentication through Keycloak (PKCE), using the `ztdf-viewer` client.

## Running it

You need Node.js and the Ztward stack running locally (`make docker-up` from the repository root).

```bash
# Build the JavaScript SDK the viewer depends on
cd sdk/js && npm ci && npm run build && cd -

# Install and start the viewer
cd samples/ztdf/ui
cp .env.example .env      # defaults point at the local Docker stack
npm ci
npm run dev
```

Open http://localhost:3002 and sign in with one of the development users from
[Keycloak setup](../../../docs/KEYCLOAK_SETUP.md). The port is fixed at 3002 because the
Keycloak client only allows redirects back to it.

### Configuration

| Variable | Default (`.env.example`) | Purpose |
|---|---|---|
| `VITE_KEYCLOAK_URL` | `http://localhost:8080` | Keycloak base URL |
| `VITE_KEYCLOAK_REALM` | `ztward` | Keycloak realm |
| `VITE_KEYCLOAK_CLIENT_ID` | `ztdf-viewer` | OIDC client for the viewer |
| `VITE_KEY_ACCESS_URL` | `http://localhost:8081` | Key Access service (gRPC-Web via Envoy) |
| `VITE_KEY_MANAGER_URL` | `http://localhost:8081` | Key Manager service (gRPC-Web via Envoy) |
| `VITE_CLIENT_KEY_EXPIRATION_MS` | `86400000` (24 hours) | Lifetime of the browser's client key |

## Getting a `.ztdf` file to open

Create one with the `ztdf-client` command-line tool, which encrypts a file or text into a `.ztdf`
file: see [`go/cmd/ztdf-client`](../../../go/cmd/ztdf-client/README.md). Whether the viewer can
open it depends on the file's policy and the signed-in user's attributes; if access is denied,
the viewer shows the reason returned by Key Access.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the development server on port 3002 |
| `npm run build` | Production build into `dist/` |
| `npm run preview` | Serve the production build |
| `npm run lint` | Run ESLint |

## More detail

[README_ZTDF.md](README_ZTDF.md) covers the implementation: the architecture, the security
properties of the browser key handling, the `ZtdfClient` and `useZtdf` APIs, and troubleshooting.

Built with React, TypeScript, Vite, Tailwind CSS and shadcn/ui.

## License

Apache-2.0. See [`samples/LICENSE`](../../LICENSE).
