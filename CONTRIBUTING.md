# Contributing to Ztward

Thanks for your interest in contributing.

## Contributor License Agreement (required)

Ztward is offered under open-source licenses (see [LICENSING.md](LICENSING.md)) and under a
commercial license. To keep offering both, every contributor must accept the
[Ztward Individual Contributor License Agreement](CLA.md) before a pull request can be merged.

In plain terms, the CLA means:

- **You keep the copyright** in your contribution.
- **You grant the project a license** to use and distribute your contribution under any terms,
  including the commercial license. This is what makes dual licensing possible.
- **Your contribution stays open source.** The project commits to keep everything it distributes
  available under the open-source license of the part of the project you contributed to.
- **You confirm the work is yours to give.** If your employer has rights in what you write, make
  sure you have their permission first.

This summary is for convenience only; [CLA.md](CLA.md) is the binding text.

**How to sign:** on your first pull request, a bot comments with a link. Sign in with your GitHub
account and accept the agreement. You only need to do this once, and it covers all your future
contributions.

**Contributing for a company?** If you contribute as part of your job, your employer may own
what you write. In that case your employer signs the
[Corporate Contributor License Agreement](CCLA.md) once, listing the employees allowed to
contribute on its behalf, and each of those employees also accepts the individual CLA on their
first pull request. Contact the maintainer at [benjamin.d.parrish@gmail.com](mailto:benjamin.d.parrish@gmail.com) 
to arrange the corporate agreement before opening your pull request.

The CLA check runs automatically on your first pull request.

## Workflow

1. Fork the repository and create a feature branch.
2. Make your changes, with tests for new functionality.
3. Run the checks:
   - Go services: `cd go && go vet ./... && go test -race ./...`
   - SDKs: `cd sdk/go && go test ./...`, `cd sdk/java && ./gradlew test`, `cd sdk/js && npm test`
   - End-to-end (with the stack running via `make docker-up`): `make tests-e2e`
4. Open a pull request describing the change and why it is needed.

## Licensing of contributions

Contributions to `sdk/` and `samples/` are licensed under Apache-2.0; contributions
elsewhere are licensed under AGPL-3.0-only, in addition to the rights granted by the CLA.

## Reporting security issues

Please do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for how to report them privately.
