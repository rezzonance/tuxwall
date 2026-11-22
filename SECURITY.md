# Security policy

TuxWall runs on the edge of people's networks, so security reports are
welcome and taken seriously. Thank you for helping keep TuxWall users safe.

## Supported versions

| Version | Security fixes |
| ------- | -------------- |
| latest 3.3.x release | yes |
| older 3.3.x releases | upgrade to the latest 3.3.x |
| 3.2.x and older | no |

Fixes ship as a new 3.3.x release through the signed APT repository
(`sudo apt update && sudo apt upgrade tuxwall`) and on the
[Releases](https://github.com/rezzonance/tuxwall/releases) page.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a
security problem.**

Report it privately through GitHub's private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**
(direct link: <https://github.com/rezzonance/tuxwall/security/advisories/new>).
Only the maintainers can see the report.

Please include:

- the TuxWall version (`dpkg-query -W tuxwall`) and the Ubuntu release;
- the affected component (see scope below) and, if you know it, the file or
  API route;
- steps to reproduce or a proof of concept, and what an attacker gains;
- whether the attacker needs to be on the WAN, the LAN/VPN, or logged in to
  the dashboard (and with which role);
- any logs or screenshots that help - **remove passwords, tokens, keys and
  your own public IP addresses first**.

## What to expect

TuxWall is a volunteer project, so handling is best effort:

- acknowledgement within about **7 days**;
- an initial assessment (confirmed / need more information / not a
  vulnerability) as soon as we can reproduce it;
- a fix in a new release, followed by a GitHub security advisory. We will
  agree on a disclosure date with you and credit you in the advisory unless
  you prefer to stay anonymous.

Please give us a reasonable amount of time to release a fix before
disclosing details publicly.

## Scope

In scope - code and packaging in this repository:

- the **dashboard and its API** (`www/`, `tuxwall.service`): authentication,
  2FA, roles, sessions, CSRF, injection, path traversal, the firewall /
  DNS / DHCP / WireGuard / backup endpoints;
- the **packages and installer**: `tuxwall-install.sh`, the `.deb`
  maintainer scripts and shipped files (`pkg/`), systemd units and their
  sandboxing, the APT repository and its signing;
- the **community ban collector** (`collector/`, the tuxwall.org API);
- **plugins** in `plugins/` and the plugin host (install, pinning,
  permissions, worker isolation);
- the **deception layer**: tarpit, canary/OpenCanary integration and
  community reporting;
- TuxWall's integration of the **AI assistant** (the agent's sudo allowlist,
  permissions, config and the dashboard's agent proxy).

Out of scope:

- vulnerabilities in third-party software TuxWall installs or talks to -
  CrowdSec, Suricata, opencode, Unbound, Kea, radvd, nginx, WireGuard,
  OpenCanary, Ubuntu packages, AI model providers. Please report those
  upstream (tell us too if TuxWall's configuration makes them worse);
- attacks that already require root on the gateway or physical access;
- denial of service by flooding the WAN link;
- the dashboard being reachable from the internet after the owner exposed it
  on purpose (it is LAN/VPN only by default);
- reports from automated scanners without a demonstrated impact.

## Verifying releases

- **APT repository**: `Release`/`InRelease` are signed with the TuxWall APT
  key, fingerprint

  ```text
  5D79 B908 2DCA EB9C CB73  1382 F5D8 2357 16BD BDD1
  ```

  published as [`apt-public.asc`](apt-public.asc) in this repository and at
  <https://rezzonance.github.io/tuxwall/public.asc>. `tuxwall-install.sh`
  refuses the repository if the key's fingerprint differs. Check it yourself:

  ```bash
  gpg --show-keys --with-fingerprint apt-public.asc
  ```

- **GitHub Releases** (3.3.2 and later) carry the exact `.deb` the APT
  repository serves, `SHA256SUMS` and `SHA256SUMS.asc` (a detached
  signature by the same key):

  ```bash
  gpg --import apt-public.asc
  gpg --verify SHA256SUMS.asc SHA256SUMS
  sha256sum -c SHA256SUMS
  ```

  The release notes say whether the checksum was verified against the
  signed APT index that published the package.
