# Security Policy

EmailEngine is a self-hosted email integration platform. It stores email account
credentials, proxies access to IMAP/SMTP, the Gmail API, and the Microsoft Graph
API, and serves a REST API and an admin web UI. We welcome responsible reports
of vulnerabilities that present a credible security risk to users. Please
distinguish security vulnerabilities from ordinary bugs, unusual edge cases, and
hardening suggestions.

## Supported Versions

Security fixes are released only against the latest major version. We do not
backport patches to older majors, so upgrading to the current release line is
the supported way to receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

If you are on an older major, please upgrade. See the release notes at
<https://github.com/postalsys/emailengine/releases> before updating.

## What Qualifies as a Security Vulnerability

A security report should identify a realistic way for an attacker to cross a
security boundary in a supported version of EmailEngine. Unexpected behavior, a
failing test, or a technically correct proof of concept is not sufficient on its
own to establish security impact.

In particular, explain:

- **Attacker capabilities:** Who is the attacker, and what inputs, systems, or
  responses can they control _without_ already having the privileges or secrets
  they are trying to gain?
- **Attack path:** How does attacker-controlled input reach the affected code
  through a supported EmailEngine interface, such as the REST API, the admin web
  UI, the hosted authentication forms, the built-in SMTP server or IMAP proxy,
  webhook delivery, or an email message that EmailEngine processes?
- **Prerequisites:** What configuration and user actions are required? If the
  attack depends on unusual options or deliberately malformed input, explain why
  those conditions could arise in a real application.
- **Impact:** What confidentiality, integrity, or availability boundary is
  crossed, and what can the attacker achieve as a result?

A vulnerability involving an optional or less common feature can still qualify
if these conditions are met. Conversely, the existence of a defensive check in
the code does not, by itself, establish that every bypass of that check has a
realistic security impact.

## Reporting a Vulnerability

**Do not disclose suspected exploitable vulnerabilities through public GitHub
issues, pull requests, or discussions before coordinating with the
maintainers.**

Report privately through one of the following channels:

1. **GitHub Security Advisories (preferred):**
   <https://github.com/postalsys/emailengine/security/advisories/new>.
2. **Email:** **andris@postalsys.com**, as listed in
   [`SECURITY.txt`](SECURITY.txt). Encrypt sensitive details if possible.

### Required Information

Please provide enough information to evaluate both the defect and its security
impact. Reports should include:

1. The affected EmailEngine version or commit, Node.js version, deployment
   method (npm, Docker, or prebuilt binary), and relevant configuration.
2. A concise description of the issue and the affected component (for example
   the REST API, admin web UI, OAuth2 flows, the built-in SMTP server or IMAP
   proxy, webhook delivery, credential encryption, or the export pipeline).
3. A minimal, tested reproduction, including steps to run it, expected behavior,
   and observed behavior.
4. A concrete threat model: attacker control, prerequisites, trust boundary, and
   resulting impact. Clearly distinguish what your reproduction proves from what
   you believe might be possible.
5. An explanation of why the issue affects real deployments beyond a
   deliberately constructed test setup, where this is not obvious.

A suggested fix is welcome but does not replace an explanation of
exploitability. A complete real-world exploit is not always necessary, but the
report must make a credible security impact clear.

### Reports That May Be Treated as Ordinary Bugs

The following generally do **not** qualify for private security handling unless
you can demonstrate an additional, meaningful security boundary crossing:

- Issues that require the attacker to control trusted application code,
  administrator-only configuration, or the secret they supposedly extract.
- Problems caused solely by application-level misuse, exposed credentials, or
  insecure deployment choices outside EmailEngine's control.
- Contrived proof-of-concept setups where the tester controls both sides of a
  request, without explaining how a separate attacker could trigger the issue.
- Parser quirks, unexpected behavior, and bypasses of internal checks with no
  demonstrated security impact.
- Speculative findings based only on static analysis or an automated tool's
  assessment, without a verified reproduction and credible attack scenario.

These may still be valid bugs and may be considered through the normal issue
tracker. Please coordinate before making any potentially exploitable details
public. Classification as a bug does not guarantee a fix or a particular
priority.

### Automated and AI-Assisted Reports

Automated analysis and AI tools are welcome as research aids, but the person
submitting a report is responsible for verifying its claims. **Do not submit
bulk, unverified, or speculative AI-generated findings.** Test each finding
against a supported release and establish the actual security impact. Reports
that do not meet the requirements above may be closed without further
investigation or individual feedback; they can be resubmitted with stronger
evidence.

## Triage and Disclosure

EmailEngine is maintained by a small team, and there is **no guaranteed response
or resolution time**. Reports are prioritized based on demonstrated impact,
exploitability, affected usage, and available maintenance resources.

A private report does not automatically become a security advisory. Confirmed
vulnerabilities may be fixed and disclosed through GitHub Security Advisories;
other findings may be closed, deferred, or handled as ordinary bugs. Please do
not disclose details of an unresolved, potentially exploitable issue publicly
without coordinating with the maintainers.

## CVEs and Credit

We do not request or manage CVE identifiers. A report being acknowledged, a bug
being fixed, or a pull request being merged does **not** mean that EmailEngine
has confirmed a security vulnerability or endorsed a CVE assignment. We do not
guarantee advisories, CVE identifiers, or public credit for reports. For
confirmed vulnerabilities disclosed through an advisory, substantive reporters
may be credited if they wish.

## Scope

In scope: the EmailEngine application source in this repository: the REST API
and admin web UI (authentication, session and token handling, CSRF protection),
OAuth2 application handling, credential encryption at rest, the built-in SMTP
server and IMAP proxy, webhook delivery (including custom filter and transform
functions), the export pipeline, and inter-worker communication.

Out of scope:

- Vulnerabilities in your own application code that integrates with EmailEngine.
- Misconfiguration of your deployment, for example exposing the admin interface
  or REST API to untrusted networks, weak service secrets, an unauthenticated or
  publicly reachable Redis instance, or missing TLS.
- Issues that require an already-compromised host or pre-existing administrator
  access.
- Vulnerabilities in third-party email providers and services that EmailEngine
  connects to (Gmail, Microsoft 365, arbitrary IMAP/SMTP servers).
- Missing security headers without a demonstrated, concrete impact.
- Social-engineering reports.

Thank you for helping keep EmailEngine and its users safe.
