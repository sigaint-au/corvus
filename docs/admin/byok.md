# Bring Your Own Key (BYOK) per project

Secret values are encrypted with Fernet before they are stored. By default a
single server-wide key (`MASTER_KEY`) is used. Projects can opt in to a
**dedicated data-encryption key (DEK)** — "bring your own key" per project.

The first supported tier generates and stores the project key **locally**
(server-side, wrapped by `MASTER_KEY`). An **external HSM** tier wraps the
project key with an HSM key-encryption key so `MASTER_KEY` is out of the DEK's
trust path; see [../dev/hsm.md](../dev/hsm.md) for setup (the guide uses a
PKCS#11 software HSM for development, but any PKCS#11 HSM works).

---

## How it works

```
MASTER_KEY (key-encryption key)  ──encrypts──►  private.project_crypto_keys.key_enc = DEK
DEK (per-project Fernet key)     ──encrypts──►  api.secrets.value_enc
```

- Each project may have exactly one active DEK (`private.project_crypto_keys`).
- Every secret row records which key encrypted it via
  `api.secrets.crypto_provider` (`'master'` or `'project'`). Version history
  snapshots carry the same marker (`api.secret_versions.crypto_provider`).
- The raw DEK is **never stored** — only the Fernet-wrapped form.
- Non-secret server settings (SMTP, LDAP, OIDC, TOTP) always use
  `MASTER_KEY`, regardless of project BYOK.

---

## Onboarding (project wizard)

Create a project via **Add project →** the new-project onboarding page
(`/teams/<team_id>/projects/new`):

1. **Basics** — name + description.
2. **Encryption** — choose:
   - **Managed — platform key** (default): secrets use the server key.
   - **Project key — bring your own key**: the wizard creates a project DEK at
     creation time. All new secrets are encrypted under it.
   - **External HSM** (shown when an HSM is configured): the project DEK is
     wrapped by the HSM's key-encryption key.
3. **Create** — review and submit.

Creating a project with BYOK records an `org_audit` event
(`project_key_created`).

## Managing keys (Project Settings → Encryption)

- **Status:** shows whether the project uses a managed (server) key or a
  dedicated project key (`local` provider) and when it was created.
- **Adopt project key** — applies a project key to a project that was created
  with the managed key (or re-encrypts legacy rows). Every secret/version still
  encrypted with `MASTER_KEY` is re-encrypted under the project DEK. The
  operation is additive (rows that fail stay `crypto_provider='master'` and
  remain readable) and audited (`project_key_adopted`).
- **Migrate to HSM** — when an HSM is configured, a `local` project can be
  migrated to an HSM-wrapped key (all secrets re-encrypted, audited as
  `project_key_migrated`).

---

## External HSM deployment for administrators

### Prerequisites

- A PKCS#11-compatible HSM (hardware, or SoftHSM2 for testing).
- The PKCS#11 module `.so` accessible from the app container.
- A token initialised with a known label and PIN.

### Configuration

```bash
export HSM_PKCS11_MODULE=/path/to/module.so
export HSM_TOKEN_LABEL=secretserver
export HSM_PIN=<your-pin>
export HSM_KEK_LABEL=byok-kek
```

`HSM_PIN` is the switch — if unset, the HSM option is hidden in the UI.

### Verification

1. Create a test project and select **External HSM**.
2. Check Project Settings → Encryption shows "External HSM · byok-kek".
3. Create a secret and reveal it — confirms the full encrypt/decrypt path.

### Backup

Back up the HSM token directory (SoftHSM2) or follow your HSM vendor's backup
procedure. Loss of the token or PIN makes HSM-backed secrets unrecoverable.

### Disaster recovery

If the HSM is lost:

- HSM-backed secrets cannot be decrypted.
- Restore the token from backup, or
- Migrate affected projects back to local BYOK (if the old DEK can be
  recovered) or to managed (server-wide key).

### What to tell users

- HSM-backed projects require the HSM to be online for all secret access.
- If the HSM is unavailable, secrets in HSM-backed projects cannot be revealed
  until it is restored.

---

## What stays on the server-wide key

- Server settings that hold secrets: SMTP password, LDAP bind password, OIDC
  client secret, and each user's TOTP secret.
- Secret values in projects that have not adopted a project key.

---

## What BYOK protects (and does not)

- **Protects:** separates encryption keys per project, so a compromise of one
  project's key (or a re-encryption mishap) does not affect other projects; and
  enables per-project key rotation later.
- **Does not protect:** the server-wide `MASTER_KEY` wraps every project DEK, so
  a compromise of `MASTER_KEY` compromises all projects regardless of BYOK.
  Projects remain in the same trust boundary as the app server. True external
  BYOK (KMS-backed keys) is required to move keys out of that boundary.

---

## Rotating MASTER_KEY

When you rotate `MASTER_KEY`, every project DEK is still wrapped with the old
key. Re-wrap them to the new key before shutting the old one down:

```bash
# with the NEW MASTER_KEY set:
MASTER_KEY_OLD=<old-master-key> flask --app app rekey-project-keys
# or: flask --app app rekey-project-keys --old-master-key <old-master-key>
```

This unwraps each DEK with the old key and re-wraps it with the current
`MASTER_KEY`. Run it once per rotation; it is idempotent (rows already wrapped
with the new key are skipped).

## Rotating the HSM KEK

```bash
flask --app app rekey-hsm-kek
```

Generates a fresh KEK, re-wraps every HSM-backed project DEK under it, and
updates each project's `kms_key_ref`. Also available from Server Settings →
Encryption ("Rotate HSM KEK").

## Migrating all local BYOK projects to HSM

Server Settings → Encryption → "Migrate all local BYOK projects to HSM" (or
per-project "Migrate to HSM" on the project Settings tab) re-encrypts local
projects onto HSM-wrapped keys.

## Reverting to managed is not offered in the UI

Downgrading a project from a dedicated key back to the server-wide key is
intentionally not exposed: it weakens the trust boundary and complicates
history. If you must, use the admin/CLI tooling to migrate (a project can be
migrated `local → hsm`; the reverse is not exposed).

---

## Roadmap / not yet shipped

- **Key rotation** — planned contract: reuse the adopt gate (team owner/admin
  or global admin), add `key_version` to `api.secrets`/`api.secret_versions`
  plus a DEK history so old ciphertext stays decryptable, require a
  confirmation step, and record an `org_audit` event (`project_key_rotated`).
- **"Require HSM" policy** — a server setting that disables Managed/Local in
  the new-project wizard so every new project must be HSM-backed.
- Per-team keys (today granularity is per-project).