# Third-party licenses

Corvus is licensed under the GNU Affero General Public License v3.0
(`LICENSE`). This file lists third-party works shipped with the application
image or vendored in the tree.

All of the following are compatible with AGPL-3.0 (permissive or LGPL).
Development-only tools (pytest, ruff, pylint, mypy, tox, mkdocs-material) are
not included in the runtime image.

## Vendored frontend

| Work | Version | License | Source |
|------|---------|---------|--------|
| htmx | 2.0.10 | 0BSD | https://github.com/bigskysoftware/htmx |
| Oat | (minified `oat.min.css` / `oat.min.js`) | MIT | https://github.com/knadh/oat — Copyright (c) 2026 Kailash Nadh |

htmx 0BSD requires no attribution. Oat’s MIT notice is reproduced below.

```
The MIT License

Copyright (c) 2026 Kailash Nadh. https://nadh.in

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## Python runtime (direct)

Pinned in `app/requirements.txt` / `pyproject.toml`. Transitive Flask/psycopg
pieces (Werkzeug, Jinja2, MarkupSafe, click, itsdangerous, blinker, cffi,
pycparser, pyasn1) are BSD/MIT and are compatible.

| Package | License |
|---------|---------|
| Flask | BSD-3-Clause |
| Werkzeug, Jinja2, MarkupSafe, itsdangerous, click | BSD-3-Clause |
| blinker | MIT |
| psycopg, psycopg-binary, psycopg-pool | LGPL-3.0-only |
| PyJWT | MIT |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| gunicorn | MIT |
| ldap3 | LGPL-3.0 |
| qrcode | BSD-3-Clause (QR Code is a trademark of DENSO WAVE) |
| python-pkcs11 | MIT |
| redis | MIT |
| cffi | MIT-0 |
| pycparser | BSD-3-Clause |
| pyasn1 | BSD-2-Clause |

LGPL libraries are imported as separate Python packages (dynamic linking).
You may replace them with other LGPL-licensed builds. Their license texts
ship inside the installed wheels.

## Container extras

The production app image is Red Hat UBI 9 (`ubi9/python-312-minimal`).
The Compose `dev` target additionally installs AlmaLinux 9 `softhsm`
(BSD-style; binary-compatible with UBI9 because SoftHSM is not in UBI
or EPEL 9). RPM copyright files stay under `/usr/share/doc/`.
