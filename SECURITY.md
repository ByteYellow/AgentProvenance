# Security Policy

[简体中文](docs/zh-CN/security.md)

## Supported Versions

Security fixes target the latest stable release. Users of older versions should
upgrade. Any additional backports will be identified in the relevant security
advisory.

## Reporting a Vulnerability

Submit a [private vulnerability report on GitHub](https://github.com/ByteYellow/AgentProvenance/security/advisories/new).
You can also find this form under **Security → Advisories → Report a vulnerability**
in the repository. Reports are handled privately rather than as public issues.

Alternatively, email [byteyellow@qq.com](mailto:byteyellow@qq.com) with the subject
"[AgentProvenance Security] Brief description". Keep vulnerability details and
exploit code private while we coordinate disclosure.

Include the affected version or commit, operating system and deployment mode,
required access, expected impact, and reproduction steps or a minimal proof of
concept. Use synthetic credentials and remove unrelated sensitive information
from attachments. An initial report is welcome even if a complete reproduction
is not yet available.

## Scope

We welcome reports affecting AgentProvenance itself, including unauthorized
access, credential exposure, unsafe handling of imported bundles or
agent-controlled content, signature-verification bypasses, evidence-integrity
failures, and exploitable resource exhaustion.

Please describe how an attacker can reach the affected component and the
resulting impact. If you are unsure whether an issue is security-related,
contact us privately.

## Response and Resolution

We aim to acknowledge reports within seven business days. After initial
assessment, we will communicate the impact, mitigation options, and expected
next steps.

Fixes are prioritized by exploitability and impact. Resolution timelines depend
on the issue; this is a maintenance target rather than a guaranteed
service-level agreement.

## Coordinated Disclosure

We will coordinate disclosure with the reporter. Published advisories will
describe affected versions, fixed versions, and available mitigations or upgrade
instructions.

We will credit reporters with their consent. Please conduct testing only on
systems and data you own or are authorized to assess.

## Other Issues

Use [GitHub Issues](https://github.com/ByteYellow/AgentProvenance/issues) for
ordinary bugs, usage questions, and feature requests.
