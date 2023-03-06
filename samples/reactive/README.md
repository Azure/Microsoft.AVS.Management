# Azure Function that executes AVS commandlet via .NET SDK
The sample demonstrates scripted deployment of Azure Function with Managed Identity to execute AVS Run Command commandlet via .NET SDK.

## Overview
Deploying multiple resources to Azure can be a challenging and error-prone task. 
This examples demonstrates:
- infrastructure-as-code approach with strong static validation that together provide high confidence and repeatbility for your deployments.
- settings propagation
- timer- and event-based trigger handlers
- AppInsights telemetry 

The deployment relies on [F# script](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/) that uses [FAKE](https://fake.build/) and [farmer library](https://compositionalit.github.io/farmer/) to succinctly capture build and deployment logic.

## Building and deploying the example

### Pre-requisites
- .NET SDK 7.x
- `az` CLI
- `func` [Azure Functions CLI](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=v4%2Cmacos%2Ccsharp%2Cportal%2Cbash)
- `azurite` [Azure Storage emulator](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite?tabs=npm) if running the function locally

1. Use `az` CLI to login.
1. Edit `deploymentArgs.fsx` and provide the details of your AVS cloud and the resource group to depoy the Functions into
1. Build and deploy everything: `dotnet fsi build.fsx`
