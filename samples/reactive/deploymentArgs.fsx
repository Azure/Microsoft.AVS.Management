open System

type AVSCloud = 
    { Subscription: Guid
      ResourceGroup: string
      Name: string }

[<NoComparisonAttribute>]
type DeploymentArgs = 
    { Subscription: Guid
      Location: string
      Name: string
      PackageId: string
      Cmdlet: string
      AVSCloud: AVSCloud
      TimerPeriod: string
      Settings: (string * string) list }
    with
        member x.ResourceGroup = $"{x.Name}-rg"
        member x.Keyvault = $"{x.Name}-kv"
        member x.Identity = $"{x.Name}-i"
        member x.Plan = $"{x.Name}-plan"
        member x.StorageAccount = sprintf "%ssa" (x.Name.Replace("-",""))
        member x.AllSettings = [ "Subscription", string x.AVSCloud.Subscription
                                 "ResourceGroup", x.AVSCloud.ResourceGroup
                                 "Name", x.AVSCloud.Name 
                                 "PackageId", x.PackageId 
                                 "TimerPeriod", x.TimerPeriod
                                 "Cmdlet", x.Cmdlet ] 
                                @ x.Settings |> Map.ofList

// Change the settings
let dev =
    { Subscription = Guid "7f1fae41-7708-4fa4-89b3-f6552cad2fc1" // the subscription to deploy the Function into
      Location = "CentralUS"                                     // Region
      Name = "avs-scripting-fn"                                  // Name template to use for all resources
                                                                 // ARM resourceId of your SDDC
      PackageId = "Microsoft.AVS.Management@5.*"                 // Package specification, note the wildcard
      Cmdlet = "Get-StoragePolicies"                             // Cmdlet to invoke
      TimerPeriod = "0 */10 * * * *"                             // Timer specification in cron format
      AVSCloud =  { Subscription = Guid "7f1fae41-7708-4fa4-89b3-f6552cad2fc1"
                    ResourceGroup = "yetolmac-canadaeast"
                    Name = "yetolmac-ca" }
      Settings = [] }