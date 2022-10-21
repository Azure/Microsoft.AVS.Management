# Execute AVS commandlet via .NET SDK
Minimal sample that demonstrates executing AVS Run Command commandlet via .NET SDK.

## Running the sample

### Pre-requisites
1. .NET SDK 5.x
1. `az` CLI if intending to impersonate the current user*
1. Edit `local.settings.json` and provide the details of your AVS cloud
1. Optional: edit `Program.cs` to provide arguments for your commandlet.
> *NOTE: See [the docs](https://docs.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) for TokenCredential for details.

Use `az` CLI to login or setup the [environment variables](https://docs.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential?view=azure-dotnet) as required then execute the sample.
