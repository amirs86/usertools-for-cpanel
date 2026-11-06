# Contributing

- Python baseline is **3.9** (`engine/`). No newer syntax.
- Perl in cPanel style: `use strict; use warnings;`.
- Privacy: tracked files must never contain hostnames, IPs, ports, real
  account or package names, emails, or names of people. Use placeholders
  (`example.com`, `<PORT>`, `uttest`) and runtime detection.
- Security: never add `chown`, `chgrp`, or any path-taking AdminBin function.
- Every new tool ships with its policy switch at `0`, enforced in its
  `_gate_tool`, `_gate_app` or inline gate. A cPanel feature with no line
  counts as enabled, so the feature list alone is never the off switch.
- New dependencies need an Apache-2.0-compatible licence and an entry in
  `THIRD_PARTY_NOTICES.md`. Never copy files, templates, CSS, JS, icons or
  text from cPanel, hosting providers or Stack Overflow.
- Run the test suite on Linux before every commit (the same commands CI runs):

```sh
python3 -m pytest tests/ -q
prove -Itests/lib -Iadmin tests/
perl tests/render_check.pl
bash tests/test_install.sh
bash tests/test_update.sh
shellcheck install.sh uninstall.sh bootstrap-install.sh bin/usertools-update \
    tests/test_install.sh tests/test_update.sh
```

## Release tarballs

Build release tarballs from a clean tag so Windows checkouts can never leak
CRLF into them (the WHM CGI shebang breaks on `\r`):

```sh
git -c core.eol=lf -c core.autocrlf=false -c tar.umask=022 archive \
    --format=tar.gz --prefix=usertools-for-cpanel-<tag>/ -o <file>.tar.gz <tag>
```

`.gitattributes` pins `* text=auto eol=lf`; `tests/test_install.sh` asserts
`git ls-files --eol` shows no `crlf` in the index or attrs, that an archive
has no CR in any text file, and the installer verifies installed files.
