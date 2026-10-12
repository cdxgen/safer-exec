# npm bootstrap for new platform packages

The release workflow (`.github/workflows/ci.yml`, job `publish`) publishes every package through npm trusted publishing: GitHub Actions proves its identity with OIDC and npm accepts the upload without a token. npm can only attach a trusted publisher to a package that already exists, so a package name the workflow has never published, such as `@cdxgen/safer-exec-windows-amd64` and `@cdxgen/safer-exec-windows-arm64`, needs a one-time setup from a maintainer's machine first.

`bootstrap.mjs` does that setup:

1. **publish** a placeholder `0.0.0` of each package (a `package.json` and a README, no code), restricted to its OS and CPU so it never installs anywhere else;
2. **trust**: tie each package to `cdxgen/safer-exec`, workflow `ci.yml`, allowed to publish;
3. **deprecate** the placeholder version, so nobody mistakes it for a release.

Every step that changes the registry is a dry run unless you pass `--yes`, and each step skips work that is already done, so the script can be re-run safely. It never touches credentials: you log in with `npm login`, and npm asks for your 2FA code (or opens the browser) itself.

## Before you start

- Node.js 20 or later, and npm 11.15 or later (`npm install -g npm@latest`); `npm trust` needs it.
- An npm account with publish rights to the `@cdxgen` scope and two-factor authentication turned on. `npm trust` refuses accounts without 2FA and tokens that bypass it.
- `npm login` done in the same terminal.

## Steps

```bash
cd .github/scripts/npm-bootstrap
```

See where things stand: your npm version, who you are logged in as, how the already-published `@cdxgen/safer-exec` is configured, and what each new package still needs.

```bash
node bootstrap.mjs check
```

Preview everything without changing the registry:

```bash
node bootstrap.mjs all
```

Do it for real. npm prompts for a 2FA code on each publish, trust and deprecate call:

```bash
node bootstrap.mjs all --yes
```

The final `check` should list a trusted publisher for both packages. Compare it with the `@cdxgen/safer-exec` entry printed at the top; if that one names a GitHub environment, add the same environment with `npm trust github <package> --repository cdxgen/safer-exec --file ci.yml --environment <name> --allow-publish` after revoking the entry the script made (`npm trust list` shows its id, `npm trust revoke <package> --id=<id>` removes it).

You can also run the steps one at a time (`publish`, `trust`, `deprecate`), or limit them to one package with `--package @cdxgen/safer-exec-windows-arm64`.

## After the setup

Tag the release as usual. The workflow publishes `1.1.0` of each Windows package with provenance, and `1.1.0` becomes the `latest` version, replacing the deprecated placeholder. The publish step skips any version that is already on the registry, so a run that stopped partway can simply be re-run.

The same procedure applies to any future platform package: add its name, `os` and `cpu` to `PACKAGES` at the top of `bootstrap.mjs`.
