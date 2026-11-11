# Ztward PAP UI

The web interface for Ztward's Policy Administration Point (PAP). Use it to write and manage the
authorization policies and entitlements that Ztward's decision service enforces, and to review the
audit log of changes.

## What you can do

- **Policies:** create, edit, enable and disable policies written in JSON, OPA (Rego) or XACML.
- **Entitlements:** grant specific subjects access to resources and actions, optionally with
  conditions and an expiry date.
- **Audit logs:** see who changed which policy or entitlement, and when.
- **Dashboard:** an overview of policies and entitlements.

Every page except sign-in requires a Keycloak login. All changes go through the PAP REST API
(`go/cmd/pap-server`), which applies the same validation and audit logging as API clients.

## Running it

### With Docker (the whole stack)

`make docker-up` from the repository root builds and starts the UI with everything else. It is
then available at http://localhost:3000. The image is built with the settings in
[`.env.docker`](.env.docker), and its nginx forwards `/api/` to the PAP service.

### For development

You need Node.js and the Ztward stack running (`make docker-up`), so that the PAP API and Keycloak
are available.

```bash
cd pap-ui
cp .env.example .env
npm ci
npm run dev
```

Open http://localhost:3000. The development server always uses port 3000, because the Keycloak
client only allows redirects back to it. If the Docker stack's UI container is running, stop it
first (`docker stop ztward-pap-ui`) to free the port.

The PAP API is served over TLS with the local development certificates from `make certs`. If the
browser rejects its certificate, trust the development CA (`config/examples/certs/ca.crt`) or
open https://localhost:8090 once and accept the certificate.

### Configuration

| Variable | Default (`.env.example`) | Purpose |
|---|---|---|
| `VITE_PAP_API_URL` | `https://localhost:8090` | PAP REST API base URL |
| `VITE_KEYCLOAK_URL` | `http://localhost:8080` | Keycloak base URL |
| `VITE_KEYCLOAK_REALM` | `ztward` | Keycloak realm |
| `VITE_KEYCLOAK_CLIENT_ID` | `ztward-pap-ui` | Public OIDC client for the UI |

These are build-time settings, embedded into the JavaScript bundle. Never put secrets in them.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the development server on port 3000 |
| `npm run build` | Production build into `build/` |
| `npm run preview` | Serve the production build |
| `npm run lint` | Run ESLint |

## More detail

- [PAP API guide](../docs/PAP_API_GUIDE.md): the REST API the UI uses
- [Policy guides](../docs/customer/policies/JSON_POLICIES.md): writing JSON, OPA and XACML policies
- [Entitlements guide](../docs/customer/entitlements/CREATING_ENTITLEMENTS.md)

Built with React, TypeScript, Vite, Tailwind CSS and shadcn/ui.

## License

AGPL-3.0-only, like the rest of the Ztward services. See [`LICENSING.md`](../LICENSING.md).
