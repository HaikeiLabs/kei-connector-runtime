# Security policy

## Reporting a vulnerability

Report security issues privately by email to
[security@haikeilabs.com](mailto:security@haikeilabs.com). Do not open a
public issue, pull request or Discord thread for a security issue.

Include:

- the kei-proxy version (`kei-proxy version`) and operating system;
- what an attacker can do, and the steps to reproduce it;
- any proof-of-concept code or logs, with secrets removed.

Do not include real credentials, runtime tokens, customer data or production
identifiers in a report.

## Scope

kei-proxy decides tool calls, releases credentials and ships audit records,
so these are in scope:

- a tool call allowed when policy should deny it, or any path that fails open;
- a credential, runtime token, prompt or tool argument that leaks into a log,
  error, audit record or network request;
- another local user reaching the runtime's Unix socket or state directory;
- tampering with the policy bundle or audit spool.

## Supported versions

Fixes go into the latest release. Upgrade to it with the installer in the
[README](README.md#install).
