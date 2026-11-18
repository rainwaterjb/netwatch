# Security policy

NetWatch watches a home network and can change router settings, so security
reports are very welcome.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. Include what you found,
how to reproduce it, and which version you ran (`/api/status` shows it).

You'll get a reply within a week. Fixes go out as a new release with a note in
`CHANGELOG.md`, and reporters are credited unless they'd rather not be.

## Supported versions

Only the latest release gets security fixes. Updating is one command
(`./update.sh`), and every release can be rolled back.

## Scope

In scope: the NetWatch application and its container image (sign-in, sessions,
tokens, single sign-on, the API, router/Pi-hole integrations, alert channels,
push notifications, metrics).

Out of scope: running NetWatch with `WEB_PASSWORD` unset or `TLS=off` (both are
documented as unsafe), and issues in your router, Pi-hole or identity provider
themselves.

## Before you post anything

Logs, screenshots and backups can contain your device names, IP and MAC
addresses, API tokens or webhook URLs. Remove them before sharing.
