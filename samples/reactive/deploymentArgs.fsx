open System

[<NoComparisonAttribute>]
type DeploymentArgs = 
    { Subscription: Guid
      Location: string
      Name: string
      PrivateCloud: Uri
      Settings: (string * string) list }
    with
        member x.ResourceGroup = $"{x.Name}-rg"
        member x.Keyvault = $"{x.Name}-kv"
        member x.Identity = $"{x.Name}-i"
        member x.Plan = $"{x.Name}-plan"
        member x.StorageAccount = x.Name.Replace("-","")
        member x.AllSettings = ["PrivateCloud", string x.PrivateCloud] @ x.Settings |> Map.ofList

// Change the settings
let dev =
    { Subscription = Guid "23995e3f-96a0-4b7a-95a0-c77f91054b52" // the subscription to deploy the Function into
      Location = "CentralUS"                                     // Region
      Name = "avs-scripting-fn"                                  // Name template to use for all resources
                                                                 // ARM resourceId of your SDDC
      PrivateCloud = Uri("/subscriptions/7f1fae41-7708-4fa4-89b3-f6552cad2fc1/resourceGroups/jatramme-r37-osa21/providers/Microsoft.AVS/privateClouds/jatramme-v37-osa21", UriKind.Relative)
      Settings = []
    }