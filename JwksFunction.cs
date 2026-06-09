using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
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

    public JwksFunction(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<JwksFunction>();
    }

    [Function("Jwks")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = ".well-known/jwks.json")] HttpRequestData req)
    {
        var cacheSeconds = GetIntEnv("JWKS_CACHE_SECONDS", 300);

        if (_cachedJwksJson != null && DateTimeOffset.UtcNow < _cacheUntil)
        {
            var cached = req.CreateResponse(System.Net.HttpStatusCode.OK);
            cached.Headers.Add("Content-Type", "application/json");
            cached.Headers.Add("Cache-Control", $"public, max-age={cacheSeconds}");
            await cached.WriteStringAsync(_cachedJwksJson);
            return cached;
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

        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(kvUri), credential);

        var jwkList = new List<Jwk>();

        foreach (var keyName in keyNames)
        {
            try
            {
                var keyResp = await keyClient.GetKeyAsync(keyName);
                var kvKey = keyResp.Value;

                if (kvKey.KeyType != KeyType.Rsa && kvKey.KeyType != KeyType.RsaHsm)
                {
                    _logger.LogWarning("Key {keyName} is not RSA (type: {type}). Skipping.", keyName, kvKey.KeyType);
                    continue;
                }

                var rsaKey = kvKey.Key;
                var n = Base64Url(rsaKey.N);
                var e = Base64Url(rsaKey.E);

                // kid: use the key name as the key ID
                var kid = kvKey.Name;

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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load key {keyName} from Key Vault.", keyName);
            }
        }

        if (jwkList.Count == 0)
        {
            return await Error(req, 500, "No usable RSA keys found to publish as JWKS.");
        }

        var jwks = new JwksResponse { Keys = jwkList };
        var json = JsonSerializer.Serialize(jwks, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        });

        _cachedJwksJson = json;
        _cacheUntil = DateTimeOffset.UtcNow.AddSeconds(cacheSeconds);

        var res = req.CreateResponse(System.Net.HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "application/json");
        res.Headers.Add("Cache-Control", $"public, max-age={cacheSeconds}");
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
