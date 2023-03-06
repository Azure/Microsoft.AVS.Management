using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Azure.ResourceManager;
using AVS.Reactive;
using Microsoft.Extensions.Logging;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(builder =>
        builder
            .AddSingleton<AVSCloudSettings>(_ => AVSCloudSettings.Load())
            .AddSingleton<ArmClient>(provider => {
                var credential = new Azure.Identity.DefaultAzureCredential(); // or use the another/specific impl 
                return new ArmClient(credential, provider.GetService<AVSCloudSettings>()?.subscriptionId);
            })
            .AddSingleton<IList<IEventHandler>>(provider => {
                var settings = provider.GetService<AVSCloudSettings>();
                var logFactory = provider.GetService<ILoggerFactory>();
                return new List<IEventHandler> { 
                    new ClusterEventHandler(settings!, logFactory!),
                    new ScriptEventHandler(settings!, logFactory!)
                };
            })
    )
    .Build();

host.Run();
