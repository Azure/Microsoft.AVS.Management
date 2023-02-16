#!/usr/bin/env -S dotnet fsi
// run `dotnet fsi build.fsx -t` to see the list of available targets

#r "nuget: Fake.Core.Target"
#r "nuget: Fake.DotNet.Cli"
#r "nuget: Fake.IO.FileSystem" 
#r "nuget: Fake.IO.Zip" 
#r "nuget: Farmer" 
#r "nuget: System.Reactive" 
#load "deploymentArgs.fsx"

open Fake.Core
open Fake.Core.TargetOperators
open Fake.DotNet
open Fake.IO
open Fake.IO.Globbing.Operators
open Farmer
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
    let deploy (args:DeploymentArgs) src =
        az (sprintf "functionapp deployment source config-zip -g %s -n %s --src %s" args.ResourceGroup args.Name src) "."

module ARM =
    // See https://compositionalit.github.io/farmer/ for documentation
    let deploy (args:DeploymentArgs) =
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
            https_only
            use_runtime FunctionsRuntime.DotNetIsolated
            use_extension_version V4
            operating_system Linux
            settings (Map.toList args.AllSettings)
            add_identity msi 
        }

        arm {
            location (Location args.Location)
            add_resources [plan; fn; sa; msi; fn]
        }
        |> Deploy.execute args.ResourceGroup Deploy.NoParameters


Target.create "clean" (fun _ ->
    !! "**/bin"
    ++ "**/obj"
    ++ "**/out"
    |> Seq.iter Shell.cleanDir
)

Target.create "restore" (fun _ ->
    DotNet.restore id "fn"
)

Target.create "start" (fun _ ->
    sh "func" "start host" "fn"
) 

Target.create "deploy" (fun _ ->
    let args = DeploymentArgs.dev

    Deploy.setSubscription args.Subscription
    |> Result.mapError (failwithf "Unable to set current subscription: %s") |> ignore
    
    printfn "Deploying ARM resources..."
    let _ = ARM.deploy args
    
    printfn "Uploading Function..."
    Fn.deploy args fnZip
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

"clean"
  ==> "restore"
  ==> "deploy"

"restore"
  ==> "start"

Target.runOrDefaultWithArguments "deploy"