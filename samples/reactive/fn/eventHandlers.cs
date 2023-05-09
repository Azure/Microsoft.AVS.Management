using System;
using System.Collections.Generic;
using Azure.Messaging.EventGrid;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Azure.ResourceManager;
using Azure.Core;
using Azure.ResourceManager.Avs;
using Azure.ResourceManager.Avs.Models;

namespace AVS.Reactive
{
    public interface IEventHandler {
        bool Supports(ResourceType resourceType);
        Task Handle(AvsPrivateCloudResource avsCloud, ResourceIdentifier resourceId, EventGridEvent input);
    }

    abstract class CloudEventHandler {
        protected AVSCloudSettings Settings { get; private set; }
        protected ILogger Log { get; private set; }
        public CloudEventHandler(AVSCloudSettings settings, ILoggerFactory loggerFactory) {
            Settings = settings; 
            Log = loggerFactory.CreateLogger(this.GetType());
        }
    }

    class ClusterEventHandler : CloudEventHandler, IEventHandler {
        public ClusterEventHandler(AVSCloudSettings settings, ILoggerFactory loggerFactory):base(settings, loggerFactory) {}
        public bool Supports(ResourceType resourceType) => resourceType == AvsPrivateCloudClusterResource.ResourceType;

        public Task Handle(AvsPrivateCloudResource avsCloud, ResourceIdentifier resourceId, EventGridEvent input)
        {
            var name = $"{Settings.cmdlet}-{DateTime.UtcNow.ToShortTimeString()}".Replace(" ","-");
            var cmdletId = ScriptCmdletResource.CreateResourceIdentifier(Settings.subscriptionId, Settings.subscriptionId, Settings.name, Settings.packageId, Settings.cmdlet);
            return ScriptExecution.Run(avsCloud, name, cmdletId);
        }
    }

    class ScriptEventHandler : CloudEventHandler, IEventHandler {
        public ScriptEventHandler(AVSCloudSettings settings, ILoggerFactory loggerFactory):base(settings, loggerFactory) {}
        public bool Supports(ResourceType resourceType) => resourceType == ScriptExecutionResource.ResourceType;

        public async Task Handle(AvsPrivateCloudResource avsCloud, ResourceIdentifier resourceId, EventGridEvent input)
        {
            var execution = await avsCloud.GetScriptExecutionAsync(resourceId.Name);
            if(execution?.Value.Data.ProvisioningState == ScriptExecutionProvisioningState.Failed)
                Log.LogError("{CmdletId} failed with: {FailureReason}", input.Subject, execution?.Value.Data.FailureReason);
        }
    }
}