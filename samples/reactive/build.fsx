#!/usr/bin/env -S dotnet fsi
// run `dotnet fsi build.fsx -t` to see the list of available targets

#r "nuget: Fake.Core.Target"
#r "nuget: Fake.DotNet.Cli"
#r "nuget: Fake.IO.FileSystem" 
#r "nuget: Fake.IO.Zip" 
#r "/Users/eugene/sources/farmer/src/Farmer/bin/Debug/netstandard2.0/Farmer.dll" 
#r "nuget: System.Reactive" 
#load "deploymentArgs.fsx"

open Fake.Core
open Fake.Core.TargetOperators
open Fake.DotNet
open Fake.IO
open Fake.IO.Globbing.Operators
open Farmer
open Farmer.Arm
open Farmer.Builders

open DeploymentArgs

// Version change is needed for a new Function impl to take effect, ideally incorporating CI build number and/or git revision
let fileVersion = Environment.environVarOrDefault "version" "0.0.0" 
let fnZip = sprintf "out/%s.zip" fileVersion

// init FAKE context, see https://fake.build for details
System.Environment.GetCommandLineArgs() 
|> Array.skip 2 // fsi.exe; build.fsx
|> Array.toList
|> Context.FakeExecutionContext.Create false __SOURCE_FILE__
|> Context.RuntimeContext.Fake
|> Context.setExecutionContext

[<AutoOpen>]
module Shell =
    let sh cmd args cwd = 
        Shell.Exec (cmd, args |> String.replace "\n" "", cwd)
        |> function 0 -> () | code -> failwithf "%s %s (in %s) exited with code: %d" cmd args cwd code
    
    let az = 
        if System.OperatingSystem.IsWindows() then "az.cmd" else "az"
        |> sh

module Fn =
    let upload (args:DeploymentArgs) src =
        az (sprintf "functionapp deployment source config-zip -g %s -n %s --src %s" args.ResourceGroup args.Name src) "."

// See https://compositionalit.github.io/farmer/ for documentation
module ARM = 
    let deploy (args:DeploymentArgs) =
        printfn "Deploying the Functions app..."
        Deploy.setSubscription args.Subscription
        |> Result.mapError (failwithf "Unable to set current subscription: %s") |> ignore

        let sa = storageAccount {
            name args.StorageAccount
        }
        let plan = servicePlan {
            name args.Plan
            sku WebApp.Sku.S1
            operating_system OS.Linux
        }
        let msi = userAssignedIdentity {
            name args.Identity
        }
        let fn = functions {
            name args.Name
            link_to_storage_account sa.Name.ResourceName
            link_to_service_plan plan.Name
            use_runtime FunctionsRuntime.DotNetIsolated
            use_extension_version V4
            operating_system Linux
            settings (Map.toList args.AllSettings)
            add_identity msi 
        }
        let outputs = 
            arm {
                location (Location args.Location)
                add_resources [plan; fn; sa; msi; fn]
                output "msi" msi.PrincipalId.ArmExpression
            }
            |> Deploy.execute args.ResourceGroup []
        Fn.upload args fnZip

        printfn "Deploying the event grid subscription..."
        Deploy.setSubscription args.AVSCloud.Subscription
        |> Result.mapError (failwithf "Unable to set current subscription: %s") |> ignore
        let cloudResourceId = Farmer.Arm.AVS.privateClouds.resourceId(ResourceName args.AVSCloud.Name)
        let runScripts =  // grant the function permissions to run the scripts on the SDDC
            { Name = sprintf "[guid(%O, '%s', '%O')]" cloudResourceId.ArmExpression.Value
                                                      msi.ResourceId.Name.Value
                                                      Roles.Contributor.Id 
              |> ResourceName
              RoleDefinitionId = Roles.Contributor
              PrincipalId = ArmExpression.literal outputs["msi"] |> PrincipalId 
              PrincipalType = PrincipalType.ServicePrincipal
              Scope = UnmanagedResource cloudResourceId
              Dependencies = Set.empty }
        let fnRef =
            { Arm.Web.siteFunctions.resourceId(ResourceName args.Name, ResourceName "eventHandler") with 
                Subscription = Some (string args.Subscription)
                ResourceGroup = Some args.ResourceGroup }
        let subs = eventGrid {
            topic_name $"{args.AVSCloud.Name}-events"
            add_function_subscriber (Unmanaged fnRef)
                { MaxEventsPerBatch = 1u; PreferredBatchSizeInKilobytes = 64u }
                [ SystemEvents.Resources.ResourceWriteSuccess; SystemEvents.Resources.ResourceActionSuccess ]
        }
        arm {
            location Location.Global
            add_resource subs
            add_resource runScripts
        }
        |> Deploy.execute args.AVSCloud.ResourceGroup []


Target.create "clean" (fun _ ->
    !! "**/bin"
    ++ "**/obj"
    ++ "**/out"
    |> Seq.iter Shell.cleanDir
)

Target.create "restore" (fun _ ->
    DotNet.restore (fun a ->
        { a with Runtime = Some "linux-x64" }) "fn"
)

Target.create "package" (fun _ ->
    DotNet.publish (fun a ->
        { a with
            NoRestore = true
            OutputPath = Some "out/fn"
            Runtime = Some "linux-x64"
            Configuration = DotNet.BuildConfiguration.Release
            MSBuildParams = { MSBuild.CliArguments.Create() with 
                                Properties = [ "Version", fileVersion
                                               "DeployTarget", "Package"
                                               "CreatePackageOnPublish","true"] } 
        }) "fn"
    System.IO.Compression.ZipFile.CreateFromDirectory("out/fn", fnZip) 
)

Target.create "start" (fun _ ->
    let args = DeploymentArgs.dev
    [ sprintf """{
        "IsEncrypted": false,  
        "Values": {
          "FUNCTIONS_WORKER_RUNTIME": "dotnet-isolated",
          "AzureWebJobsStorage": "UseDevelopmentStorage=true",
          "TimerPeriod": "%s",
          "Subscription": "%O",
          "ResourceGroup": "%s",
          "Name": "%s",
          "PackageId": "%s",
          "Cmdlet": "%s"
        }
    }""" args.TimerPeriod
         args.Subscription
         args.AVSCloud.ResourceGroup
         args.AVSCloud.Name
         args.PackageId
         args.Cmdlet]
    |> File.write false "fn/local.settings.json"
    
    // see https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-local
    [ async { sh "azurite" "--location out" "." }
      async { sh "func" "start host" "fn" } ]
    |> Async.Parallel
    |> Async.RunSynchronously
    |> ignore
) 

Target.create "deploy" (fun _ ->
    let args = DeploymentArgs.dev
    
    printfn "Deploying ARM resources..."
    ARM.deploy args |> ignore
)

Target.create "upload" (fun _ ->
    let args = DeploymentArgs.dev
    
    printfn "Pushing the implementation..."
    Fn.upload args fnZip |> ignore
)

"clean"
  ==> "restore"
  ==> "package"
  ==> "deploy"

"restore"
  ==> "start"

"package"
  ==> "upload"

Target.runOrDefaultWithArguments "deploy"