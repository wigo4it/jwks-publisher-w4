# JWKS Publisher - Azure Function App

> Overgenomen van [`wigo4it/azure-jwks-publisher`](https://github.com/wigo4it/azure-jwks-publisher) (Mark Nekeman, juni 2026) op 22 september 2026 en sindsdien beheerd door CE&E als referentie-implementatie voor gemeenten die API's van Wigo4it aanroepen met `private_key_jwt`. Wijzigingen gaan via een PR; team `@wigo4it/ce-e` is eigenaar.

An Azure Function App that publishes RSA public keys from Azure Key Vault as a [JWKS (JSON Web Key Set)](https://datatracker.ietf.org/doc/html/rfc7517) endpoint. This allows JWT validators to retrieve your signing keys via the standard `/.well-known/jwks.json` path.

## Endpoint

```
GET /.well-known/jwks.json
```

Returns a JWKS document containing the public RSA keys configured in Azure Key Vault. The endpoint requires no authentication (anonymous access).

### Example response

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "my-signing-key",
      "n": "leRJALN_-BSU9FF...",
      "e": "AQAB"
    }
  ]
}
```

## Key rotation

With the default settings the endpoint publishes the two newest enabled versions of every configured key, each with `kid` = `<key name>-<key version>`. Rotate a key by creating a new version (manually with `az keyvault key rotate`, or automatically with a rotation policy: `az keyvault key rotation-policy update --vault-name <vault> --name <key> --value policy.json`). The new version appears in the JWKS next to the previous one within `JWKS_CACHE_SECONDS`. The signing application must sign with the current version and put the same `kid` (`<name>-<version>`, the version is `KeyVaultKey.Properties.Version`) in the token header; a validator that caches keys by `kid`, such as Keycloak, then fetches the JWKS again and accepts the new key without any downtime. Disable or delete a version in Key Vault to remove it from the JWKS.

## Prerequisites

- .NET 8.0 SDK
- An Azure subscription with:
  - An **Azure Function App** (Windows, .NET 8 isolated worker)
  - An **Azure Key Vault** containing one or more RSA keys
  - A **System-assigned managed identity** enabled on the Function App

## App Settings

| Setting | Required | Description |
|---|---|---|
| `KEYVAULT_URI` | Yes | The URI of your Azure Key Vault, e.g. `https://my-vault.vault.azure.net/` |
| `JWKS_KEY_NAMES` | Yes | Comma-separated list of key names in Key Vault to publish, e.g. `key-signing-1,key-signing-2` |
| `JWKS_CACHE_SECONDS` | No | How long to cache the JWKS response in memory (default: `300` seconds) |
| `JWKS_KEY_VERSIONS` | No | How many of the newest enabled versions of each key to publish, each with its own `kid` (default: `2`). Publishing the current and the previous version is what makes key rotation seamless for consumers that select keys by `kid`. |
| `JWKS_KID_MODE` | No | `name-version` (default): `kid` is `<key name>-<key version>`, unique per version. `name`: legacy behaviour, only the current version with `kid` = key name (no seamless rotation). |

## Key Vault Permissions

The Function App's managed identity needs the following permission on the Key Vault:

- **Key Get** — to read the public key material

You can assign this via:

- **RBAC**: Assign the `Key Vault Crypto User` role to the Function App's managed identity
- **Access Policy**: Grant `Get` under Key permissions to the Function App's managed identity

## Setup

### 1. Create and import a signing key

Generate an RSA keypair locally. The private key stays with your signing application; only the public key is imported into Key Vault for the JWKS endpoint to serve.

```bash
# Generate keypair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Import the public key into Key Vault
az keyvault key import \
  --vault-name <your-vault-name> \
  --name <key-name> \
  --pem-file public.pem
```

Configure `private.pem` in your JWT-issuing application. Consumers will verify tokens by fetching the public key from the `/.well-known/jwks.json` endpoint.

### 2. Enable managed identity

```bash
az functionapp identity assign \
  --name <function-app-name> \
  --resource-group <resource-group>
```

### 3. Grant Key Vault access (RBAC)

```bash
PRINCIPAL_ID=$(az functionapp identity show \
  --name <function-app-name> \
  --resource-group <resource-group> \
  --query principalId -o tsv)

az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee $PRINCIPAL_ID \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>
```

### 4. Configure app settings

```bash
az functionapp config appsettings set \
  --name <function-app-name> \
  --resource-group <resource-group> \
  --settings \
    KEYVAULT_URI="https://<your-vault>.vault.azure.net/" \
    JWKS_KEY_NAMES="<key-name-1>,<key-name-2>"
```

## Deployment

### Option A: VS Code

1. Install the **Azure Functions** extension
2. Press `F1` → **Azure: Sign In**
3. Press `F1` → **Azure Functions: Deploy to Function App**

### Option B: Azure CLI

```bash
dotnet publish JwksPublisher.csproj -c Release -o ./publish

cd publish
# Important: use -Force to include hidden folders (.azurefunctions)
powershell -Command "Compress-Archive -Path (Get-ChildItem -Path '.' -Force) -DestinationPath '../deploy.zip' -Force"
cd ..

az functionapp deployment source config-zip \
  --name <function-app-name> \
  --resource-group <resource-group> \
  --src deploy.zip
```

> **Note**: When creating the zip on Windows with PowerShell, you must use `Get-ChildItem -Force` to include the `.azurefunctions` folder. Without it, the Functions runtime will not discover the function.

## Project Structure

| File | Description |
|---|---|
| `JwksFunction.cs` | The function that reads keys from Key Vault and returns JWKS JSON |
| `Program.cs` | Function App host configuration |
| `host.json` | Host settings — route prefix set to empty string for clean URLs |
| `web.config` | IIS configuration to allow `.well-known` paths (dot-prefixed paths are blocked by default on Windows) |

## Caching

The function uses in-memory caching per instance. After the first request, the JWKS response is cached for `JWKS_CACHE_SECONDS` (default 300). The `Cache-Control` header is also set to allow downstream HTTP caching.

Cache refreshes are serialized with a lock, so when the cache expires only a single request calls Key Vault while concurrent requests wait for the refreshed result (preventing a cache stampede).

If a refresh fails (e.g. Key Vault is temporarily unreachable) and a previously cached JWKS is available, that last-known-good response is served for a short retry window (30s) instead of returning an error. This keeps downstream token validation working during transient Key Vault outages. A `500` is only returned when no cached value exists yet.

## Supported Key Types

Currently only **RSA** keys (including RSA-HSM) are supported. Non-RSA keys are skipped with a warning log.
