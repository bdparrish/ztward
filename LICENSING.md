# Licensing

Ztward is dual-licensed. Copyright 2026 Benjamin Parrish.

## Open-source licenses

| Path | License | File |
|---|---|---|
| Everything not listed below (services, `go/`, `pap-ui/`, `proto/`, `deployment/`, `config/`, `scripts/`) | GNU Affero General Public License v3.0 only (`AGPL-3.0-only`) | [`LICENSE`](LICENSE) |
| `sdk/go`, `sdk/java`, `sdk/js`, `sdk/python` | Apache License 2.0 (`Apache-2.0`) | `sdk/*/LICENSE` |
| `samples/` | Apache License 2.0 (`Apache-2.0`) | [`samples/LICENSE`](samples/LICENSE) |
| `third_party/gin` | MIT (modified fork of gin-gonic/gin) | [`third_party/gin/LICENSE`](third_party/gin/LICENSE) |

Third-party dependencies keep their own licenses.

### What this means in practice

- **Using the SDKs** in your own application, open or closed source, is governed by Apache-2.0.
- **Running the Ztward services** is governed by AGPL-3.0. If you modify them and let others
  interact with your modified version over a network, you must offer those users the
  corresponding source code of your modifications under AGPL-3.0.

## Commercial license

If the AGPL-3.0 terms do not fit your use (for example, offering a modified Ztward as a
proprietary hosted service, or embedding the services in a closed product), a commercial
license is available. Contact: [benjamin.d.parrish@gmail.com](mailto:benjamin.d.parrish@gmail.com).

## License enforcement code

The services include optional offline license checks (`go/pkg/licensing`, the license
middleware, and the `go/cmd/license-signer` tool). They exist for commercially licensed
builds and are **off by default** (`license.enabled: false`, see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md)). With the default setting, the open-source
build runs with no license file and no limits.

This code is part of the AGPL-3.0 source like everything else: you may read, modify, or remove
it in your own copy. The signing private key is not in this repository, so only the maintainer
can issue license tokens for commercial builds.

## Contributions

Contributions are accepted under a Contributor License Agreement so the project can continue to
offer both the open-source and commercial licenses. See [CONTRIBUTING.md](CONTRIBUTING.md).
