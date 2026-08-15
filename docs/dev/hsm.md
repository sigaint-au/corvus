# External HSM (SoftHSM2) for BYOK

BYOK projects can use an **external HSM** as their key-encryption key (KEK).
For local development the external HSM is [SoftHSM2](https://www.opendnssec.org/softhsm/),
a software PKCS#11 token. The same PKCS#11 interface works with a real network
HSM in production by configuring a named slot's PKCS#11 URL.

---

## How it works

- Each HSM slot holds an AES-256 **KEK** (labelled by the slot URL's `object`
  segment). The KEK never leaves the HSM.
- Each BYOK project still has a 32-byte Fernet **data-encryption key (DEK)**
  for its secrets. For HSM-backed projects the DEK is wrapped with the HSM KEK
  (AES-CBC) instead of `MASTER_KEY`.
- `private.project_crypto_keys.key_enc` holds the wrapped DEK,
  `key_provider='hsm'`, and `kms_key_ref` = the KEK label. `api.secrets`/
  `api.secret_versions.crypto_provider` stays `'project'` for HSM-backed
  projects — the difference is only *where the DEK is unwrapped*.

Value encryption/decryption is unchanged (Fernet); `MASTER_KEY` is no longer in
the trust path for HSM-backed projects' DEKs.

## Containerised SoftHSM2 (dev)

`compose.yml` adds a `softhsm2` service (built from `softhsm2/Dockerfile`) that
initialises the token into a shared `hsmdata` volume, plus the `app` service
mounts the same volume and loads `libsofthsm2.so`:

```
softhsm2  ──init token──►  hsmdata:/hsm/tokens  ◄──mount──  app (libsofthsm2.so + python-pkcs11)
```

Both services mount the volume at ``/hsm/tokens`` (not the package path
``/var/lib/softhsm``, which is mode ``770`` root:softhsm and blocks the
non-root app user).

Run the stack as usual:

```bash
ALLOW_INSECURE_DEFAULTS=1 scripts/up.sh
```

The token is created on first boot (`softhsm2/init.sh`), then the app can create
HSM-backed projects.

## App configuration (env)

The app holds **no global HSM configuration** — HSM access is configured per
**named slot** (a PKCS#11 URL in `private.hsm_slots`). The only runtime env is
`SOFTHSM2_CONF` (compose sets it to the shared token directory's `softhsm2.conf`
so `libsofthsm2.so` can find the token); everything else lives in each slot's
URL.

**DEK format:** project keys are Fernet keys (`Fernet.generate_key()`, 44-byte
urlsafe base64). The HSM wraps the decoded 32 raw bytes (AES key-wrap when
supported, else AES-CBC). Unwrap returns a Fernet key again.

## Code map

| File | Role |
|------|------|
| `app/hsm.py` | PKCS#11 wrapper: `parse_pkcs11_url`/`redact_pkcs11_url`/`has_inline_pin`, `generate_kek`/`delete_kek`, and slot-aware `available_for_slot`/`status_for_slot`/`ensure_kek_for_slot`/`wrap_dek_for_slot`/`unwrap_dek_for_slot`/`wrap_dek_with_label`/`test_connection_for_slot` |
| `app/config.py` | `master_key_is_default()` (no HSM env vars) |
| `app/crypto.py` | `_dek_for()` dispatches unwrap by `key_provider` (local vs hsm) and `hsm_slot_id` via `_slot_url()`; `project_dek()`; `slot_url()`/`clear_slot_url_cache()`; `encrypt_for_project`/`decrypt_for_project` |
| `app/project_keys.py` | `ensure_project_key(provider, hsm_slot_id)`, `adopt_project_key`, `migrate_project_key(target_slot_id)`, `rotate_hsm_kek(slot_id)`, `encryption_summary`, `migrate_all_local_to_hsm(target_slot_id)`, `link_legacy_to_slot`, `rewrap_project_keys` |
| `db/migrations/0027_hsm_slots.sql` | `private.hsm_slots` table + `api.list_hsm_slots`/`hsm_slot_url`/`hsm_slot_upsert`/`hsm_slot_delete` |
| `softhsm2/` | Dev token-initialiser container |

## Manual SoftHSM2 setup (no compose)

```bash
# install
sudo apt-get install softhsm2 opensc
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# init a token
softhsm2-util --init-token --free --label secretserver --so-pin 1234 --pin 1234
```

Then create a slot in **Server Settings → Encryption → HSM slots** with a
PKCS#11 URL (see below), e.g.:

```
pkcs11:token=secretserver;object=byok-kek?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234
```

---

## PKCS#11 URL format (RFC 7512)

Named slots store a PKCS#11 URI instead of env vars. The app parses it with
`hsm.parse_pkcs11_url()`:

```
pkcs11:token=<label>;object=<KEK label>[;slot-id=<n>]?module-path=<.so>[&pin-source=<file>|&pin-value=<pin>]
```

| Component | Use |
|-----------|-----|
| `token` | Token/slot label |
| `object` | KEK object label (used as `kms_key_ref`) |
| `slot-id` | Optional slot ID |
| `module-path` | PKCS#11 module path **required** |
| `pin-source` | File path to read the PIN from |
| `pin-value` | PIN inline (redacted in the UI as `***`) |

Example (SoftHSM2 dev, PIN in a file):

```
pkcs11:token=secretserver;object=byok-kek?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=/run/secrets/hsm-pin
```

## Multi-slot architecture

- **`private.hsm_slots`** holds named PKCS#11 URL configurations (admin-managed
  from Server Settings → Encryption). `private.project_crypto_keys.hsm_slot_id`
  links a project's DEK to a slot.
- **Slot-aware functions** (`ensure_kek_for_slot`, `wrap_dek_for_slot`,
  `unwrap_dek_for_slot`, `available_for_slot`, `status_for_slot`,
  `test_connection_for_slot`) parse the slot URL and operate against that
  module/token instead of the global env vars.
- The **crypto layer** resolves a project's slot URL via `crypto._slot_url()`
  (cached, 64 entries) and unwraps with the slot's KEK; both the slot-URL and
  project-key caches are cleared together after key events.
- **Backward compatibility**: pre-slot projects have `hsm_slot_id IS NULL` and
  cannot be decrypted until linked to a slot. The wizard offers "HSM" only when
  named slots exist.
- **Linking legacy projects**: once a slot's KEK label matches a legacy
  project's `kms_key_ref`, use the "Link legacy project(s)" action — a
  metadata-only `UPDATE` (no re-encryption). The slot must be reachable
  (`available_for_slot`) before linking; the KEK label is verified against the
  live token.

## `test_connection_for_slot` behavior

Returns `(True, msg)` when the token is reachable, **even if the KEK is missing**
— the KEK is created lazily on first use. Returns `(False, error)` only when the
session cannot be opened (module not found, token missing, wrong PIN, etc.).

## `has_inline_pin`

```python
hsm.has_inline_pin(url: str) -> bool
```

Returns `True` when the URL contains `pin-value=` (inline PIN). Used by the admin
UI to warn that inline PINs are stored in the database. Prefer `pin-source=`
(file-based PIN).

## Notes / caveats

- SoftHSM2 is a **local library**, not a network HSM — the token directory must
  be shared with the app (hence the shared volume).
- The PKCS#11 calls in `app/hsm.py` are written for SoftHSM2 2.6 + `python-pkcs11`
  0.7. If you point at a real HSM, verify its AES-CBC key-wrap behaviour.
- MASTER_KEY rotation (`rekey-project-keys`) skips HSM-backed rows: their DEKs
  don't depend on `MASTER_KEY`.
- Loss of the HSM token (or PIN) makes HSM-backed secrets unrecoverable —
  back up the token directory.
