# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately by either:

* email to **admin@opsbreak.com**, or
* GitHub private vulnerability reporting: the **Security** tab of
  [Opsbreak/trailhunt](https://github.com/Opsbreak/trailhunt/security) ->
  **Report a vulnerability**.

Please include the affected version or commit, a description of the issue and
its impact, and steps or a sample input to reproduce it.

## What to expect

* We acknowledge reports within **3 business days**.
* We investigate, keep you informed of progress, and agree on a fix and
  disclosure timeline with you.
* We practice **coordinated disclosure**: please give us a reasonable
  opportunity to release a fix before details are made public. We will credit
  you in the release notes unless you prefer to remain anonymous.

## Scope

In scope: the `trailhunt` code in this repository - for example a crafted log
file that causes code execution, writes outside the requested output path, or
makes the tool silently skip events or rules (a detection bypass in the
engine, as opposed to a rule that could be tuned).

Out of scope: false positives / false negatives of individual detection rules
(please open a normal issue or pull request), and vulnerabilities in
third-party dependencies that are not exploitable through trailhunt.

## Supported versions

Security fixes are made on the latest release.
