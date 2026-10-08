# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- No secrets in the repository. `.env.example` contains empty values only. Compose refuses to
  start without the required secrets. `.env` and `certs/` are git-ignored.
- The CA private key never leaves `certs/ca/`. Only the server certificate, server key and CA
  certificate are mounted into the Graylog container, read-only.
- Only the web interface (loopback) and the log inputs are published. MongoDB (authentication
  enabled, least-privilege Graylog user) and OpenSearch stay on the internal compose network.
- Remote TCP inputs use TLS. Clients verify the server certificate name, and mutual TLS is
  available.
- Provisioning reads credentials from the environment or `0600` files only, passes them to
  curl outside the process list, refuses plain HTTP to remote hosts, and has no option to
  disable TLS verification.
- CI runs shellcheck, yamllint, ruff, JSON validation, compose validation, bats tests, an
  end-to-end integration test and a gitleaks scan. Actions are pinned to commit SHAs and run
  with `contents: read`.
