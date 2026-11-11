# Ztward

**Zero Trust Data Format (ZTDF) platform with attribute-based access control.**

Ztward protects data with the Zero Trust Data Format: files are encrypted once, and every
decryption asks Ztward for a key. Each request is checked against policies, entitlements and
classification levels before a key is released, so access can change or be revoked after the data
has been shared.

## What it does

- **Attribute-based access control:** decisions use attributes of the subject, the resource and
  the request context (IP address, time, environment).
- **Classification hierarchies:** NATO/DoD, commercial and financial levels, plus custom ones.
- **ZTDF and STANAG 4774:** create and open ZTDF files, with NATO STANAG 4774 support.
- **Key management:** the Key Manager and Key Access services wrap and release data keys; HSMs,
  smart cards and YubiKeys are supported, and there is a FIPS 140-3 build.
- **Policy administration:** write policies in JSON, OPA (Rego) or XACML through the PAP API, the
  CLI or the web UI.
- **SDKs:** Go, JavaScript, Python and Java.

## Quick start

You need Go 1.25 or later and Docker.

```bash
git clone https://github.com/bdparrish/ztward.git
cd ztward

make docker-up     # build images and start every service
make tests-e2e     # run the end-to-end checks against the stack
make docker-down   # stop everything
```

`make docker-up` generates local development TLS certificates the first time it runs. The
services then listen on:

| Service | Address |
|---|---|
| Platform (decisions) | `localhost:50051` (gRPC) |
| Key Manager | `localhost:50052` (gRPC) |
| Key Access | `localhost:50053` (gRPC) |
| PAP API | `https://localhost:8090` |
| Keycloak | `http://localhost:8080` (realm `ztward`) |

## Where to go next

- **Set it up:** [Configuration](CONFIGURATION.md) and [Keycloak setup](KEYCLOAK_SETUP.md).
- **Control access:** write [policies](customer/policies/JSON_POLICIES.md) and
  [entitlements](customer/entitlements/CREATING_ENTITLEMENTS.md), and read how
  [attribute-based access control](api-attribute-based-access-control.md) works.
- **Protect files:** [create ZTDF files](ZTDF_CREATION.md).
- **Build on it:** follow the [Go client tutorial](customer/samples/GOLANG_CLIENT_SAMPLE.md) or
  pick an SDK from the navigation.
- **Run it in production:** see [FIPS 140-3](SECURITY_FIPS.md) and the
  [observability runbook](OBSERVABILITY_RUNBOOK.md).

## License

The services are licensed under AGPL-3.0; the SDKs, samples and demos under Apache-2.0. A
commercial license is also available. See
[LICENSING.md](https://github.com/bdparrish/ztward/blob/main/LICENSING.md).
