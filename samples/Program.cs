using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Azure.Management.Avs;
using Microsoft.Azure.Management.Avs.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Rest;

namespace AVSScripting
{
    class Settings
    {
        public string SubscriptionId { get; set; }
        public string AVSResourceGroup { get; set; }
        public string AVSCloudName { get; set; }
        public string CommandletId { get; set; }

        public static Settings Load()
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("local.settings.json", false)
                .Build();
            var settings = new Settings();
            config.Bind(settings);
            return settings;
        }
    }
    
    class TokenCredentialServiceClientCredentials : ServiceClientCredentials
    {
        private TokenCredential _tokenCredential;
        private readonly string[] _scopes;
        private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

        public TokenCredentialServiceClientCredentials(TokenCredential tokenCredential, string[] scopes)
        {
            _tokenCredential = tokenCredential ?? throw new ArgumentNullException(nameof(tokenCredential));
            _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        }

        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var token = await _cache.GetOrCreateAsync(string.Join("#", _scopes), async e =>
            {
                var accessToken = await _tokenCredential.GetTokenAsync(new TokenRequestContext(_scopes), cancellationToken);
                e.AbsoluteExpiration = accessToken.ExpiresOn;
                return accessToken.Token;
            });
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await base.ProcessHttpRequestAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
    
    class Program
    {
        static void Main(string[] args)
        {
            var settings = Settings.Load();
            var credential = new Azure.Identity.DefaultAzureCredential(); // or use the another/specific impl 
            var tokenProvider = new TokenCredentialServiceClientCredentials(credential, new[] {"https://management.core.windows.net/.default"});
            var client = new AvsClient(tokenProvider)
                { SubscriptionId = settings.SubscriptionId };
            var execution = new ScriptExecution
            {
                ScriptCmdletId = settings.CommandletId,
                Parameters = new List<ScriptExecutionParameter>(),
                Retention = System.Xml.XmlConvert.ToString( TimeSpan.FromMinutes(30)),
                Timeout = System.Xml.XmlConvert.ToString( TimeSpan.FromMinutes(3)),
            };
            var started = client.ScriptExecutions.CreateOrUpdate(settings.AVSResourceGroup, 
                settings.AVSCloudName, $"{settings.CommandletId.Split('/').Last()}-{DateTime.Now.Second}", execution);
        }
    }
}