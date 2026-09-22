using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

public class JwksFunction
{
    private readonly ILogger _logger;

    // simpele in-memory cache (per function instance)
    private static DateTimeOffset _cacheUntil = DateTimeOffset.MinValue;
    private static string? _cachedJwksJson;

    // serialiseert het verversen zodat bij gelijktijdige cache-misses maar
    // één request Key Vault aanroept (voorkomt cache-stampede).
    private static readonly SemaphoreSlim _refreshLock = new(1, 1);

    // korte retry-window wanneer we noodgedwongen stale data serveren, zodat
    // Key Vault niet bij elke request opnieuw wordt benaderd tijdens een storing.
    private const int StaleRetrySeconds = 30;

    public JwksFunction(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<JwksFunction>();
    }

    [Function("Jwks")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = ".well-known/jwks.json")] HttpRequestData req)
    {
        var cacheSeconds = GetIntEnv("JWKS_CACHE_SECONDS", 300);

        // Fast path: serveer verse cache zonder lock.
        var cached = _cachedJwksJson;
        if (cached != null && DateTimeOffset.UtcNow < _cacheUntil)
        {
            return await Json(req, cached, cacheSeconds);
        }

        var kvUri = Environment.GetEnvironmentVariable("KEYVAULT_URI");
        if (string.IsNullOrWhiteSpace(kvUri))
        {
            return await Error(req, 500, "Missing KEYVAULT_URI app setting.");
        }

        var keyNamesRaw = Environment.GetEnvironmentVariable("JWKS_KEY_NAMES") ?? "";
        var keyNames = keyNamesRaw
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (keyNames.Length == 0)
        {
            return await Error(req, 500, "Missing JWKS_KEY_NAMES app setting (comma-separated key names).");
        }

        // Rotatie: publiceer per sleutel de N nieuwste ingeschakelde versies, elk met een
        // eigen kid (<naam>-<versie>). Zo staat de nieuwe versie naast de oude, en kiest een
        // validator (Keycloak) op kid de juiste sleutel. JWKS_KID_MODE=name geeft het oude
        // gedrag: alleen de huidige versie, kid = sleutelnaam (geen rotatie zonder onderbreking).
        var versionCount = Math.Max(1, GetIntEnv("JWKS_KEY_VERSIONS", 2));
        var kidMode = (Environment.GetEnvironmentVariable("JWKS_KID_MODE") ?? "name-version").Trim().ToLowerInvariant();
        if (kidMode == "name")
        {
            versionCount = 1;
        }

        await _refreshLock.WaitAsync();
        try
        {
            // Double-check: een ander request kan de cache hebben ververst terwijl we wachtten.
            cached = _cachedJwksJson;
            if (cached != null && DateTimeOffset.UtcNow < _cacheUntil)
            {
                return await Json(req, cached, cacheSeconds);
            }

            try
            {
                var json = await BuildJwksAsync(kvUri, keyNames, versionCount, kidMode);
                if (json != null)
                {
                    _cachedJwksJson = json;
                    _cacheUntil = DateTimeOffset.UtcNow.AddSeconds(cacheSeconds);
                    return await Json(req, json, cacheSeconds);
                }

                // Geen bruikbare sleutels deze ronde: val terug op laatst-bekende-goede JWKS
                // zodat token-validatie bij consumers niet breekt.
                if (_cachedJwksJson != null)
                {
                    return await ServeStale(req, cacheSeconds, "No usable RSA keys returned");
                }
                return await Error(req, 500, "No usable RSA keys found to publish as JWKS.");
            }
            catch (Exception ex)
            {
                // Key Vault onbereikbaar: serveer stale cache i.p.v. hard falen.
                if (_cachedJwksJson != null)
                {
                    _logger.LogError(ex, "Key Vault refresh failed; serving last-known-good JWKS.");
                    return await ServeStale(req, cacheSeconds, "Key Vault refresh failed");
                }
                _logger.LogError(ex, "Key Vault refresh failed and no cached JWKS is available.");
                return await Error(req, 500, "Unable to retrieve signing keys.");
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task<string?> BuildJwksAsync(string kvUri, string[] keyNames, int versionCount, string kidMode)
    {
        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(kvUri), credential);

        var jwkList = new List<Jwk>();

        foreach (var keyName in keyNames)
        {
            try
            {
                foreach (var kvKey in await LoadVersionsAsync(keyClient, keyName, versionCount))
                {
                    if (kvKey.KeyType != KeyType.Rsa && kvKey.KeyType != KeyType.RsaHsm)
                    {
                        _logger.LogWarning("Key {keyName} is not RSA (type: {type}). Skipping.", keyName, kvKey.KeyType);
                        continue;
                    }

                    var rsaKey = kvKey.Key;
                    var n = Base64Url(rsaKey.N);
                    var e = Base64Url(rsaKey.E);

                    // kid: sleutelnaam plus versie, zodat elke versie een unieke kid heeft;
                    // in mode "name" alleen de naam (compatibel met eerdere consumers).
                    var kid = kidMode == "name" ? kvKey.Name : $"{kvKey.Name}-{kvKey.Properties.Version}";

                    jwkList.Add(new Jwk
                    {
                        Kty = "RSA",
                        Use = "sig",
                        Alg = "RS256",
                        Kid = kid,
                        N = n,
                        E = e
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load key {keyName} from Key Vault.", keyName);
            }
        }

        if (jwkList.Count == 0)
        {
            return null;
        }

        var jwks = new JwksResponse { Keys = jwkList };
        return JsonSerializer.Serialize(jwks, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        });
    }

    // De N nieuwste ingeschakelde versies van een sleutel, nieuwste eerst. Met N = 1 is dit
    // de huidige versie (zelfde als GetKeyAsync(keyName)).
    private static async Task<List<KeyVaultKey>> LoadVersionsAsync(KeyClient keyClient, string keyName, int versionCount)
    {
        var result = new List<KeyVaultKey>();
        if (versionCount == 1)
        {
            var current = await keyClient.GetKeyAsync(keyName);
            result.Add(current.Value);
            return result;
        }

        var versions = new List<KeyProperties>();
        await foreach (var props in keyClient.GetPropertiesOfKeyVersionsAsync(keyName))
        {
            if (props.Enabled == false)
            {
                continue;
            }
            versions.Add(props);
        }

        foreach (var props in versions
                     .OrderByDescending(p => p.CreatedOn ?? DateTimeOffset.MinValue)
                     .Take(versionCount))
        {
            var key = await keyClient.GetKeyAsync(keyName, props.Version);
            result.Add(key.Value);
        }

        return result;
    }

    // Serveert de laatst-bekende-goede JWKS en zet een korte retry-window zodat
    // Key Vault niet bij elke request opnieuw wordt benaderd tijdens een storing.
    private async Task<HttpResponseData> ServeStale(HttpRequestData req, int cacheSeconds, string reason)
    {
        var staleMaxAge = Math.Min(StaleRetrySeconds, cacheSeconds);
        _cacheUntil = DateTimeOffset.UtcNow.AddSeconds(staleMaxAge);
        _logger.LogWarning("{reason}; serving last-known-good JWKS for up to {seconds}s.", reason, staleMaxAge);
        return await Json(req, _cachedJwksJson!, staleMaxAge);
    }

    private static async Task<HttpResponseData> Json(HttpRequestData req, string json, int maxAge)
    {
        var res = req.CreateResponse(System.Net.HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "application/json");
        res.Headers.Add("Cache-Control", $"public, max-age={maxAge}");
        await res.WriteStringAsync(json);
        return res;
    }

    private static async Task<HttpResponseData> Error(HttpRequestData req, int code, string message)
    {
        var res = req.CreateResponse((System.Net.HttpStatusCode)code);
        res.Headers.Add("Content-Type", "application/json");
        await res.WriteStringAsync($@"{{""error"":""server_error"",""error_description"":""{EscapeJson(message)}""}}");
        return res;
    }

    private static string EscapeJson(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    private static int GetIntEnv(string name, int fallback)
        => int.TryParse(Environment.GetEnvironmentVariable(name), out var v) ? v : fallback;

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private class JwksResponse
    {
        public List<Jwk> Keys { get; set; } = new();
    }

    private class Jwk
    {
        public string? Kty { get; set; }
        public string? Use { get; set; }
        public string? Alg { get; set; }
        public string? Kid { get; set; }
        public string? N { get; set; }
        public string? E { get; set; }
    }
}
