# Security policy

## Supported versions

bonsai-ninja is pre-1.0 software. Security fixes are made on `main` and in the
most recent GitHub release. Older release lines are not maintained unless a
release advisory explicitly says otherwise.

## Report a vulnerability privately

Do not open a public issue for a vulnerability that could put users or their
source code at risk. Use GitHub's private vulnerability reporting for this
repository. If that interface is unavailable, email `contact@gromhacks.com`
with the subject `bonsai-ninja security report`.

Include the affected version or commit, operating system and architecture,
impact, reproduction steps, and any suggested mitigation. Do not include
third-party source code or credentials unless you are authorized to share
them.

Reports are normally acknowledged within five business days. We will confirm
scope, coordinate remediation and disclosure, and credit the reporter when
requested. Please allow a reasonable remediation window before public
disclosure.

False positives, false negatives, incomplete static resolution, and rulepack
coverage gaps are welcome as normal issues when they do not reveal an
exploitable weakness in the analyzer itself.

## Release integrity

Release archives have SHA-256 checksum files and GitHub artifact attestations
signed through Sigstore. Verify both before installing a downloaded binary;
the commands are documented in `docs/getting-started.mdx`.
