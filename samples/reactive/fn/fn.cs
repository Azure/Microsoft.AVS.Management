// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName={functionname}
using System;
using System.Collections.Generic;
using Azure.Messaging.EventGrid;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Azure.ResourceManager;
using Azure.Core;
using Azure.ResourceManager.Avs;
using Azure;

namespace AVS.Reactive
{
    public class Fn
    {
        private readonly ILogger logger;
        private readonly ArmClient armClient;
        private readonly AvsPrivateCloudResource avsCloud;
        private readonly IList<IEventHandler> handlers;
        private readonly AVSCloudSettings settings;

        public Fn(ILoggerFactory loggerFactory, AVSCloudSettings settings, ArmClient armClient, IList<IEventHandler> handlers)
        {
            this.logger = loggerFactory.CreateLogger<Fn>();
            this.settings = settings;
            this.armClient = armClient;
            this.avsCloud = armClient.GetAvsPrivateCloudResource(AvsPrivateCloudResource.CreateResourceIdentifier(settings.subscriptionId, settings.resourceGroup, settings.name));
            this.handlers = handlers;
        }

        [Function("eventHandler")]
        public Task HandleEvent([EventGridTrigger] EventGridEvent input)
        {
            this.logger.LogInformation("{subject}: {data}", input.Subject, input.Data);
            if (ResourceIdentifier.TryParse(input.Subject, out var resourceId)) {
                return Task.WhenAll(handlers.Where(h => h.Supports(resourceId!.ResourceType)).Select(h => h.Handle(avsCloud, resourceId!, input)));
            }
            else return Task.CompletedTask;
        }

        [Function("timerHandler")]
        public Task HandleTimer([TimerTrigger("%TimerPeriod%", RunOnStartup = false)] TimerInfo timer)
        {
            var name = $"{settings.cmdlet}-{DateTime.UtcNow.ToShortTimeString()}".Replace(" ","-");
            var cmdletId = ScriptCmdletResource.CreateResourceIdentifier(settings.subscriptionId, settings.subscriptionId, settings.name, settings.packageId, settings.cmdlet);
            return ScriptExecution.Run(avsCloud, name, cmdletId);
        }
    }
}
