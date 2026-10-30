# Security policy

Please report vulnerabilities privately through GitHub Security Advisories
on this repository ("Report a vulnerability" under the Security tab). Do not
open public issues for security bugs.

Design rules that any report should be measured against:

- The engine (`engine/perm_engine.py`) never follows symlinks, refuses to
  run as root, and never changes owner or group (no `chown`/`chgrp`).
- The privileged Admin modules (Manage Shell, App Helper primary docroot)
  take no paths, accept only fixed enums or booleans, and derive the
  username from the caller identity only.
