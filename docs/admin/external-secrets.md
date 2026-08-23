# External Secrets Operator

Wire [External Secrets Operator](https://external-secrets.io/) (ESO) to this
app with the **webhook** provider. ESO talks to `/eso/v1` using a project
machine token (`ss_…`).

| Direction | ESO object | HTTP | Token role |
|-----------|------------|------|------------|
| **Pull** (Secret Server → cluster) | `ExternalSecret` | `GET` | `service-reveal` |
| **Push** (cluster → Secret Server) | `PushSecret` | `PUT` | `service-write` |

Use **two SecretStores**. A store’s `method` is shared: GET for pull, PUT for
push. One store cannot do both.

Copy-paste manifests:

- Pull: [../eso-pull.yaml](../eso-pull.yaml)
- Push: [../eso-push.yaml](../eso-push.yaml)

Machine tokens, roles, and allow-lists: [machine-tokens.md](machine-tokens.md).
HTTP API: [api.md](../dev/api.md).

---

## 1. Prerequisites

- ESO installed in the cluster (`SecretStore`, `ExternalSecret`, and
  `PushSecret` CRDs). Tested with ESO **v2.3** (`external-secrets.io/v1`
  stores; `PushSecret` is `v1alpha1`).
- Secret Server reachable from ESO controller pods (in-cluster DNS or the
  public HTTPS URL).
- A **team → project** with the secrets you want to sync.
- **Administration → Server settings → General → Server URL** set to the
  public base URL (no trailing slash). The project **Integrations** tab uses
  that as the YAML default.

ESO pods must be able to open TCP to the app. A host firewall that only
allows 80/443 will block a raw `:8080` URL on a workstation.

---

## 2. Create machine tokens

Project → **Integrations** (or **Machine accounts**), or the CLI:

```bash
export SS_URL=https://secrets.example.com
export SS_TOKEN=pat_…          # your PAT, to create machine tokens
export SS_PROJECT=<project-uuid>

# Pull
secretserver create token eso-pull --role service-reveal --expires-days 90

# Push (separate token)
secretserver create token eso-push --role service-write --expires-days 90
```

Copy each `ss_…` value immediately. Optional `--scope 'API_KEY,DB_*'` limits
keys. Empty allow-list = every key in the project.

| Role | Pull values | Push / rotate |
|------|-------------|---------------|
| `service-read` | no | no |
| `service-reveal` | **yes** | no (403 on PUT) |
| `service-write` | yes | **yes** |

Machine tokens skip per-secret human ACLs and reveal-approval. Prefer a
**dedicated project** and/or a **key allow-list**.

The Kubernetes Secret that holds the token **must** be labelled
`external-secrets.io/type: webhook` or the webhook provider refuses it.

---

## 3. Webhook URL

```text
{base}/eso/v1/projects/{project_id}/secrets/{key}
```

`project_id` is the project UUID (not the name). ESO fills `{key}` from the
manifest.

| From | `{base}` example |
|------|------------------|
| Same cluster | `http://secretserver-app.secretserver.svc:8080` |
| Public TLS | `https://secrets.example.com` |

Keep the `{{ .remoteRef.key }}` / `{{ .remoteRef.remoteKey }}` template on
**one line**. A folded YAML URL injects a newline and the request 401s or 404s.

Auth header that works:

```yaml
Authorization: "Bearer {{ .auth.token }}"
```

(`{{ .auth.secret.token }}` is wrong and returns 401.)

Pull reads `$.value` from the JSON body. Extra fields on the response are
ignored.

---

## 4. Pull: Secret Server → cluster

ESO `GET`s each key and writes a Kubernetes Secret.

1. Create a `service-reveal` token.
2. Apply the token Secret + SecretStore + ExternalSecret (below or
   [eso-pull.yaml](../eso-pull.yaml)).
3. Confirm the store is `Ready` and the ExternalSecret is `SecretSynced`.

Replace `PROJECT_ID`, `ss_…`, host, namespace, and key names.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-machine-token
  namespace: default
  labels:
    external-secrets.io/type: webhook
stringData:
  token: "ss_REPLACE_WITH_REVEAL_TOKEN"
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: secretserver-webhook
  namespace: default
spec:
  provider:
    webhook:
      url: "https://secrets.example.com/eso/v1/projects/PROJECT_ID/secrets/{{ .remoteRef.key }}"
      method: GET
      timeout: "10s"
      result:
        jsonPath: "$.value"
      headers:
        Authorization: "Bearer {{ .auth.token }}"
        Accept: "application/json"
      secrets:
        - name: auth
          secretRef:
            name: secretserver-machine-token
            key: token
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: default
spec:
  refreshInterval: 1m
  secretStoreRef:
    name: secretserver-webhook
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: DATABASE_URL
    - secretKey: API_KEY
      remoteRef:
        key: API_KEY
```

```bash
kubectl apply -f secretserver-eso-pull.yaml
kubectl get secretstore secretserver-webhook
kubectl get externalsecret app-secrets
# STORE Ready, ExternalSecret SecretSynced
kubectl get secret app-secrets
```

The project **Integrations** tab can generate the token Secret + pull
SecretStore (not the ExternalSecret). Paste keys into `spec.data` yourself.

In-cluster (headless Service is fine — DNS returns pod IPs):

```yaml
url: "http://secretserver-app.secretserver.svc:8080/eso/v1/projects/PROJECT_ID/secrets/{{ .remoteRef.key }}"
```

---

## 5. Push: cluster → Secret Server

ESO `PUT`s a Kubernetes Secret key to
`/eso/v1/projects/{id}/secrets/{remoteKey}` with body `{"value":"…"}`.

1. Create a **`service-write`** token (reveal-only tokens 403).
2. Apply a **second** SecretStore with `method: PUT` and a `body` template.
3. Apply a source Secret and a `PushSecret`.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secretserver-write-token
  namespace: default
  labels:
    external-secrets.io/type: webhook
stringData:
  token: "ss_REPLACE_WITH_WRITE_TOKEN"
---
apiVersion: v1
kind: Secret
metadata:
  name: app-push-src
  namespace: default
stringData:
  PUSH_KEY: "replace-me"
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: secretserver-webhook-push
  namespace: default
spec:
  provider:
    webhook:
      url: "https://secrets.example.com/eso/v1/projects/PROJECT_ID/secrets/{{ .remoteRef.remoteKey }}"
      method: PUT
      timeout: "10s"
      result:
        jsonPath: "$.value"
      body: '{"value": "{{ index .remoteRef .remoteRef.remoteKey }}"}'
      headers:
        Authorization: "Bearer {{ .auth.token }}"
        Accept: "application/json"
        Content-Type: "application/json"
      secrets:
        - name: auth
          secretRef:
            name: secretserver-write-token
            key: token
---
apiVersion: external-secrets.io/v1alpha1
kind: PushSecret
metadata:
  name: app-push
  namespace: default
spec:
  refreshInterval: 1m
  updatePolicy: Replace
  deletionPolicy: None
  secretStoreRefs:
    - name: secretserver-webhook-push
      kind: SecretStore
  selector:
    secret:
      name: app-push-src
  data:
    - match:
        secretKey: PUSH_KEY
        remoteRef:
          remoteKey: PUSH_KEY
```

Full file: [../eso-push.yaml](../eso-push.yaml).

```bash
kubectl apply -f secretserver-eso-push.yaml
kubectl get secretstore secretserver-webhook-push
kubectl get pushsecret app-push
# STATUS Synced

# Confirm in Secret Server (CLI or curl):
secretserver get secret PUSH_KEY -o value
```

`deletionPolicy: None` leaves the Secret Server row when you delete the
PushSecret. `Delete` would require a DELETE mapping; this webhook store does
not define one.

The `body` template JSON-encodes only a simple string. Quotes, newlines, or
`{{` inside the value will break the template — keep push values plain, or
escape them before they land in the source Secret.

Pull `{{ .remoteRef.key }}` and push `{{ .remoteRef.remoteKey }}` are different
template fields. Do not mix them.

---

## 6. ClusterSecretStore

Use a namespaced `SecretStore` unless several namespaces must share one
store. For `ClusterSecretStore`, every `secretRef` needs `namespace:`:

```yaml
secrets:
  - name: auth
    secretRef:
      name: secretserver-machine-token
      namespace: secretserver
      key: token
```

---

## 7. Check and troubleshoot

```bash
kubectl get secretstore,externalsecret,pushsecret
kubectl describe externalsecret app-secrets
kubectl describe pushsecret app-push
kubectl logs -n external-secrets deploy/external-secrets --since=10m
```

| Symptom | Likely cause |
|---------|----------------|
| ExternalSecret `401` | Wrong auth template (`{{ .auth.secret.token }}`), missing token, or folded URL |
| ExternalSecret `403` | Token is `service-read`; need `service-reveal` |
| PushSecret `403` | Token is not `service-write` |
| `404` / empty | Key missing, or outside the token allow-list |
| Store not Ready / “secret does not contain needed label” | Token Secret missing `external-secrets.io/type: webhook` |
| `No route to host` / timeout | ESO cannot reach the app (NetworkPolicy, firewall, wrong URL) |
| Push synced but value unchanged | Store still on GET, or `body` template not `{"value":…}` |

Successful pull and push are audited (`revealed` / `machine_upsert`) on the
project **Audit log** tab.

---

## Related docs

- [machine-tokens.md](machine-tokens.md): roles, allow-lists, UI generator
- [authentication.md](authentication.md): `ss_…` / `pat_…` flows
- [api.md](../dev/api.md): `/eso/v1` GET, PUT, POST, DELETE
- [cli.md](../user/cli.md): `secretserver create token` / `get secret`
- [eso-pull.yaml](../eso-pull.yaml): pull manifests
- [eso-push.yaml](../eso-push.yaml): push manifests
