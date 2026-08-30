# deploy

Site-specific values live in `overlays/`, never `base/`.
Worked example: `overlays/corvus-syd`.
Also: `overlays/prod`, `overlays/staging`.

Verify:
- `kubectl kustomize deploy/overlays/<name>`
- `kubectl diff -k deploy/overlays/<name>`

Do not apply. Do not cat the whole `base/` tree.
App bootstrap secrets are cluster Secrets, not git.