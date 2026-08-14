# External HSM (SoftHSM2) for BYOK

BYOK projects can use an **external HSM** as their key-encryption key (KEK).
For local development the external HSM is [SoftHSM2](https://www.opendnssec.org/softhsm/),
a software PKCS#11 token. The same PKCS#11 interface works with a real network
HSM in production by pointing `HSM_PKCS11_MODULE` / `HSM_TOKEN_LABEL` / `HSM_PIN`
at it.

---

## How it works

- The HSM holds a single AES-256 **KEK** (label `HSM_KEK_LABEL`, default
  `byok-kek`). The KEK never leaves the HSM.
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

| Variable | Default | Purpose |
|----------|---------|---------|
| `HSM_PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 module path |
| `HSM_TOKEN_LABEL` | `secretserver` | Token label |
| `HSM_PIN` | `1234` | User PIN (also the init PIN) |
| `HSM_KEK_LABEL` | `byok-kek` | AES KEK label within the token |
| `SOFTHSM2_CONF` | (package default) | SoftHSM config path; compose sets this to the shared volume conf |

`HSM_PIN` must be set and the token must open successfully for
`hsm.available()` to be true (UI hides HSM otherwise). The KEK is created
lazily on the first HSM-backed project (`hsm.ensure_kek()`).

**DEK format:** project keys are Fernet keys (`Fernet.generate_key()`, 44-byte
urlsafe base64). The HSM wraps the decoded 32 raw bytes (AES key-wrap when
supported, else AES-CBC). Unwrap returns a Fernet key again.

## Code map

| File | Role |
|------|------|
| `app/hsm.py` | PKCS#11 wrapper (`available`, `ensure_kek`, `wrap_dek`, `unwrap_dek`) |
| `app/config.py` | `HSM_*` env vars |
| `app/crypto.py` | `_dek_for()` dispatches unwrap by `key_provider` (local vs hsm) |
| `app/project_keys.py` | `ensure_project_key(provider='hsm')` wraps the DEK via the HSM |
| `softhsm2/` | Dev token-initialiser container |

## Manual SoftHSM2 setup (no compose)

```bash
# install
sudo apt-get install softhsm2 opensc
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# init a token
softhsm2-util --init-token --free --label secretserver --so-pin 1234 --pin 1234

# run the app with:
export HSM_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export HSM_TOKEN_LABEL=secretserver
export HSM_PIN=1234
```

## Notes / caveats

- SoftHSM2 is a **local library**, not a network HSM — the token directory must
  be shared with the app (hence the shared volume).
- The PKCS#11 calls in `app/hsm.py` are written for SoftHSM2 2.6 + `python-pkcs11`
  0.7. If you point at a real HSM, verify its AES-CBC key-wrap behaviour.
- MASTER_KEY rotation (`rekey-project-keys`) skips HSM-backed rows: their DEKs
  don't depend on `MASTER_KEY`.
- Loss of the HSM token (or PIN) makes HSM-backed secrets unrecoverable —
  back up the token directory.
