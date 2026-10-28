# Security policy

## Supported versions

Security fixes go into the latest minor release. While mcpward is 0.x, that's the newest
`0.y` series.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub security advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Don't open a public issue.

Include the affected version, a description of the issue, and, if you can, a reproduction or a
failing test. You can expect a first response within 7 days.

## Scope

mcpward validates access tokens and enforces authorization for MCP servers, so reports about
any of these are in scope:

- A token that should be refused but is accepted, or a policy that can be bypassed.
- A token, secret, or assertion reaching logs, handler code, or a downstream host it shouldn't.
- A request that can make the server fetch keys more often than the configured rate limit.

The RSA keys under `crates/mcpward-testing/keys/` are public test keys. Their presence in the
repository is not a vulnerability.
