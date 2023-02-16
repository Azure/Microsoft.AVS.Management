# Azure Function that executes AVS commandlet via .NET SDK
The sample demonstrates scripted deployment of Azure Function with Managed Identity to execute AVS Run Command commandlet via .NET SDK.

## Deploying the example

### Pre-requisites
- .NET SDK 7.x
- `az` CLI
- `func` [Azure Functions CLI](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=v4%2Cmacos%2Ccsharp%2Cportal%2Cbash)

1. Use `az` CLI to login.
1. Edit `deploymentArgs.fsx` and provide the details of your AVS cloud
1. Build and deploy everything: `dotnet fsi build.fsx`
