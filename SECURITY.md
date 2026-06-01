# Security Policy

EmailEngine is a self-hosted email integration platform that stores email
account credentials and proxies access to IMAP/SMTP, the Gmail API, and the
Microsoft Graph API. Because it handles sensitive credentials and message
content, we take security reports seriously and aim to respond quickly.

## Supported Versions

Security fixes are released only against the latest version. We do not backport
patches to older releases - upgrading to the current release line is the
supported way to receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

If you are on an older version, please upgrade. See the release notes at
<https://github.com/postalsys/emailengine/releases> before updating.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through one of the following channels:

1. **GitHub Security Advisories (preferred).** Open a private report at
   <https://github.com/postalsys/emailengine/security/advisories/new>. This keeps
   the discussion private until a fix is published and lets us credit you.
2. **Email.** Send details to **andris@postalsys.com** (the contact listed in
   [`SECURITY.txt`](SECURITY.txt)). Encrypt sensitive details if possible.

When reporting, please include as much of the following as you can:

- The affected version(s) and environment (EmailEngine version, Node.js version,
  OS, deployment method - npm, Docker, or prebuilt binary).
- The component involved (e.g. REST API, admin web UI, OAuth2 flows, IMAP/SMTP
  proxy server, webhook delivery, credential encryption, the export pipeline).
- A clear description of the issue and its impact (e.g. authentication bypass,
  privilege escalation, credential disclosure, SSRF, injection, information
  disclosure, denial of service).
- A minimal proof of concept or reproduction steps.
- Any suggested remediation, if you have one.

We are a small team, so there is no guaranteed response time - sometimes reports
are handled within hours, sometimes they take longer. Accepted issues are fixed
in a new release and coordinated through a GitHub Security Advisory, and
reporters who wish to be named are credited.

## CVEs

We track and disclose vulnerabilities through GitHub Security Advisories. We do
not request or manage CVE identifiers ourselves. If you need a CVE assigned for a
reported issue, please request one yourself - for example, through GitHub's own
CVE request flow on the published advisory, or another CNA.

## Scope

In scope: the EmailEngine application source in this repository - the REST API
and admin web UI (authentication, session and token handling, CSRF protection),
OAuth2 application handling, credential encryption at rest, the IMAP/SMTP and
IMAP proxy servers, webhook delivery (including custom filter/transform
functions), the export pipeline, and inter-worker communication.

Out of scope:

- Vulnerabilities in your own application code that integrates with EmailEngine.
- Misconfiguration of your deployment - for example, exposing the admin
  interface or REST API to untrusted networks, weak service secrets, an
  unauthenticated or publicly reachable Redis instance, or missing TLS.
- Issues that require an already-compromised host or pre-existing administrator
  access.
- Vulnerabilities in third-party email providers and services that EmailEngine
  connects to (Gmail, Microsoft 365, arbitrary IMAP/SMTP servers).
- Social-engineering reports and missing security headers without a
  demonstrated, concrete impact.

Thank you for helping keep EmailEngine and its users safe.
