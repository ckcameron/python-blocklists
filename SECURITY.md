# Security Policy

## Reporting a vulnerability

Use **Report a vulnerability** on the repository’s [Security Advisories](https://github.com/ckcameron/python-blocklists/security/advisories) page to send a private report. If you cannot use GitHub’s reporting form, email the [maintainer](mailto:chase@ckcameron.net) with the subject `python-blocklists security report`.

Keep suspected vulnerabilities out of public issues, pull requests, and discussions while the report is being assessed. Use the [issue chooser](https://github.com/ckcameron/python-blocklists/issues/new/choose) for ordinary bugs and feature requests.

Include the affected commit and component, the relevant OS, Python, kernel or tool versions, the conditions under which the behavior occurs, and the security impact. A short, redacted log or report excerpt can help. Omit credentials, private feed URLs, internal addresses, and unrelated production data.

## Versions

The current `main` branch is the reference for security triage. If you found an issue on another revision, include its commit and say whether it affects `main` if you know.

## Scope and trust boundaries

`python-blocklists` compiles IPv4, IPv6, and domain feeds into lists and Linux enforcement installers. The generator needs no elevated privileges and writes a bundle. Applying an installer is a separate administrative action that can change firewall, resolver, TCP Wrappers, or eBPF state.

Feed contents, DNS answers, and packets arriving at a covered interface are untrusted. The operator controls feed selection, explicit exclusions, tool paths, output locations, and where a bundle is installed. Treat generated installers as privileged code: review them and keep them in a location that untrusted users cannot modify before applying them.

The generator, generated files and installers, and the TC eBPF classifier and loader are in scope. These are the properties they are expected to preserve:

- Feed and DNS data stay data. They must not become executable code, inject configuration directives, or cause writes outside the intended outputs. Generation must not apply policy to the host.
- IP optimization preserves the effective address set, and DNS enrichment does not override explicit IP or domain exclusions.
- Install and removal operations act on their intended files and rules, preserve unrelated configuration, and respect ownership of TC filters and pinned state.
- Installed rules enforce the selected blocklists on the paths and resolvers they cover. eBPF checks both endpoints on attached ingress and egress paths.

## Impact and deployment limits

Reports should explain who can reach the affected path, what access they need, and what they can change, disclose, disrupt, or cause the system to allow. Examples include command or configuration injection from untrusted input, unintended privileged changes, disclosure of sensitive data, or failure to enforce a block on a covered path.

DNS answers change and an IP address may serve several domains. Feed quality and shared address effects are normally operational issues; report them privately if they also break a security property above. DNS blocking applies to clients using the configured resolver. TCP Wrappers applies to services that use libwrap. eBPF coverage depends on attachment and network namespace, and an administrator with the relevant privileges can change the rules or detach the program. Those limits do not rule out failures within the intended coverage.

See the [deployment guide](https://github.com/ckcameron/python-blocklists/wiki/Deployment) and [eBPF guide](https://github.com/ckcameron/python-blocklists/wiki/eBPF) for the supported deployment paths, update behavior, and recovery procedures.
