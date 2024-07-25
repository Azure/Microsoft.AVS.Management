# Overview
These guidelines layout responsibilities for Microsoft and 3rd party PowerShell script developers.
AVS Scripting functionality is exposed as standard [ARM resource](https://github.com/Azure/azure-rest-api-specs/blob/master/specification/vmware/resource-manager/Microsoft.AVS/stable/2021-06-01/vmware.json), vendors should familiarize themselves with the capabilities available.

----

# Responsibilities of AVS

AVS Scripting environment is expecting to run scripts targeted for vCenter via PowerCLI from VMware. 


## Administration Level logins

The 3rd Party script will not have access to administrator password.  Prior to executing a 3rd Party script, AVS will establish administrator level login sessions with vCenter.    This will allow any API within vCenter to be accessed.  There will be two logins established:

- The first login will be done with PowerCLI's [Connect-VIServer](https://developer.vmware.com/docs/powercli/latest/vmware.vimautomation.core/commands/connect-viserver/#Default) cmdlet.
- The second login will be done with VMware's [Connect-SsoAdminServer](https://github.com/vmware/PowerCLI-Example-Scripts/tree/master/Modules/VMware.vSphere.SsoAdmin).


## Environment

AVS will expose some standard runtime options via PowerShell variables.  See below table for current list.

| Var | Description | Usage example |
| ------- | ----------- |--|
| `VC_ADDRESS` | IP Address of VCenter | Script authors now can also use `"vc"` - hostname instead of the address |
| `SddcDnsSuffix` | Domain suffix of the SDDC |  |
| `SddcResourceId` | ARM ResourceId of the SDDC | "/subscriptions/7f1fae41-7708-4fa4-89b3-f6552cad2fc1/resourceGroups/myRG/providers/Microsoft.AVS/privateClouds/myCloud" |
| `AadAuthority` | Azure Active Directory address in this Azure Cloud | "https://login.microsoftonline.com/" |
| `PersistentSecrets` | Hashtable for keeping secrets across package script executions | `$PersistentSecrets.ManagementAppliancePassword = '***'` |
| `SSH_Sessions` | Dictionary of hostname to [Lazy](https://docs.microsoft.com/en-us/dotnet/api/system.lazy-1?view=netcore-2.1) instance of [posh-ssh session](https://github.com/darkoperator/Posh-SSH/blob/master/docs/New-SSHSession.md) | `Invoke-SSHCommand -Command "uname -a" -SSHSession $SSH_Sessions["esx.hostname.fqdn"].Value`. Another key to the dictionary is `"VC"` for SSH to vCenter.
| `SFTP_Sessions` | Dictionary of hostname to [Lazy](https://docs.microsoft.com/en-us/dotnet/api/system.lazy-1?view=netcore-2.1) instance of [posh-ssh sftp session](https://github.com/darkoperator/Posh-SSH/blob/master/docs/New-SFTPSession.md) | `New-SFTPItem -ItemType Directory -Path "/tmp/zzz" -SFTPSession $SSH_Sessions[esx.hostname.fqdn].Value`. Another key to the dictionary is `"VC"` for SFTP to vCenter

> <b>Persistent secrets</b>: 
> - The secrets are kept in a Keyvault, they are isolated on package name basis, shared across all versions of your package and made available for each of your package scripts. Delete secrets by setting the hastable entry to an empty string or `$null`. [See the secret naming constraints](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?tabs=HTTP#uri-parameters).
> - The secrets are only stored on succesful commandlet termination, any exceptions will prevent the persistence.

The script shall assume the directory it is executed in is temporary and can use it as needed, with ~25GB of space available. This environment including any files will be torn down after the script execution.

## Script Execution

Script executions are serialized (executed one at a time) for the safety of all parties.

If a script executes against an SDDC in the `Updating` state it will result in an error.  A script can set the SDDC state to `Updating` using an `AVSAttribute`, see below.

## Script Termination

AVS will terminate the script if it runs beyond the established AVS scripting timeout period. Timeout will be defaulted to 30 minutes unless one is provided by the script author (see `AVSAttribute` below).  The max timeout value is one hour.  The timeout value can override on a per-cmdlet basis.

## Script Review

AVS will review the scripts and attempt to run them.  Where necessary it is expected that the script author will provide support to AVS during this process.

----

# Responsibilities of 3rd Party 

These guidelines are expected to help scripts be more robust and supportable.  The guidelines are also to help avoid negative impact to the AVS customer's Private Cloud.

## Never login with cloudadmins through script

A Module should not attempt to login to vCenter with the AVS provided `cloudadmins` or any other role. Scripts that use `Connect-VIServer` or `Connect-SsoAdminServer` will not be allowed to run against an AVS Private Cloud.

## Never elevate privileges for cloudadmins

A Module should not attempt to elevate privileges for the AVS provided `cloudadmins` role.  Scripts that attempt to do this will not be allowed to run against an AVS Private Cloud. Elevating privileges for cloudadmin could have unintended consequences by giving elevated access to anyone using cloudadmin. The script is already logged in with administrator privileges and does not require elevating `cloudadmins` role.

## Never use cloudadmin as the user for any installed software

If necessary, use the installation script to create a separate vCenter user and role to give it.  Recommendation is to use the `cloudadmins` role as a base by duplicating it, then add necessary elevated privileges to the new role.  The privileges required for the new role will need to be reviewed by Microsoft. 
> Always add the created account to `CloudAdmins` SSO group.

### Protecting service credentials
If deploying an appliance in customer infrastruture that needs service credentials with privileges above `cloudadmins` role the vendor must ensure that the credentials are never exposed - not in-flight, nor at rest.
- The appliance user must not be able to gain root access or direct access to the storage or file system where credentials are stored.
- The appliance must be deployed in a folder with ReadOnly permission to `CloudAdmins` SSO group. See `[AVSSecureFolder]::Root()` and `[AVSSecureFolder]::GetOrCreate()`.
- The objects deployed into the secure folder must subseqently be re-secured with `[AVSSecureFolder]::Secure()` method.
- The credentials must be passed as OVA properties to the appliance, including the rotation scenario.
- The credentials must never be logged, no diagnostic bundle may include the credentials.
- The vendor must provide the cmdlets to rotate the service account password and perform any appliance updates, including security patches.
- When passing the credentials to vCenter the appliance must enforce HTTPS with host authentication.
- Use `PersistentSecrets` if access to credentials is required by the scripts later.

### Other information protection
If deploying an appliance, the appliance may not expose any VMware logs directly to the customer, any logs and diagnostics from the VMware infrastructure must go through AVS where they can be filtered for sensitive information.
AVS provides syslog forwarding that makes relevant logs available in Azure.

## Top-level functionality should be exposed as functions with [CmdletBinding](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_cmdletbindingattribute?view=powershell-7.1) taking all the inputs as the named parameters.

Secrets and additional attributes:
- Use `PSCredential` and `SecureString` if taking credentials or secrets as inputs. These parameters are encrypted while inflight and at rest and will never be echoed back to the user.
- The functions and parameters must have user-friendly description, using standard PS facilities.
- All names must follow PowerShell [naming guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/required-development-guidelines?view=powershell-7.3#use-only-approved-verbs-rd01).
- Apply `AVSAttribute` as show in [this example](https://www.powershellgallery.com/packages/Microsoft.AVS.Management/1.0.31/Content/Microsoft.AVS.Management.psm1) to specify the default timeout, SDDC status and whether it is intended to be invoked only through automation for your scripts.

Other supported parameter types:
- `System.String`
- `System.Double`
- `System.Boolean`
- `System.Int32`

> IMPORTANT: `String` parameters must be [validated/sanitized](https://learn.microsoft.com/en-us/mem/configmgr/apps/deploy-use/learn-script-security#powershell-parameters-security) against script injection if used in script generation.

If you need another parameter type please make sure it supports automatic conversion from `String`, as all the other parameter types will be taken as text.

Optional parameters are supported, however the commandlets should not use dynamic or conditional parameters. For example if value of one parameter/switch affects optionality/meaning of other parameters the commandlet should be split into two or more commandlets - where each new commandlet is tailored for the specific use-case therefore avoiding the need for the switch. Commandlets will be statically analyzed to determine the parameters and all the parameters will be presented for the user to specify. 


## Outputs and termination of a function.
The script execution pipeline supports following PowerShell streams:
- Output
- Information 
- Warning
- Error

Use the stream appropriate for the purpose, suppress outputs with `Out-Null` for information that doesn't not help with the installation or troubleshooting. 
Be aware that content of these streams is always stored as strings. Objects emitted into these streams should either be primitives (strings, ints, etc), of type `HashTable` or be explicitly converted to string by your script, otherwise they may fail to deserialize and won't be captured.
> Note that in PowerShell an expression that produces a value (for example, `Stop-VM` or `$true`) will emit that value into `Output` stream unless it's either captured in a variable or piped into `Out-Null`. We observe that this may disrupt outputs to other streams, so make sure to be intentional and eliminate any unintended outputs.

Use `-ErrorAction Stop` or equivalent means to terminate with an error and indicate the final status to the user.

On successful execution a script may assign `NamedOutputs` hashmap/dictionary to return the named key/value pairs to the user, for example:
```powershell
$NamedOutputs = @{}
$NamedOutputs['k1'] = 'v1'
$NamedOutputs['k2'] = 2 # the value will be converted to string, convert it yourself if need to return complex types

Set-Variable -Name NamedOutputs -Value $NamedOutputs -Scope Global

```

This object will be available in the [ARM resource properties](https://github.com/Azure/azure-rest-api-specs/blob/master/specification/vmware/resource-manager/Microsoft.AVS/stable/2021-06-01/vmware.json#L6921).


## Spawning child processes.
Spawning child processes is not supported at this time and must be avoided. Please find PowerShell-native alternative.


## Scripts should be packaged as a module and published as a nuget package.

Private AVS package repository will be used to install the modules. For the purpose of testing and review publish the package to [PowerShell Gallery](https://www.powershellgallery.com/).

> <b>IMPORTANT</b>: Vendors must test their package using a Linux [PowerShell container](https://hub.docker.com/_/microsoft-powershell), connecting to their on-prem datacenter.
> <b>IMPORTANT:</b> When publishing the package, please ensure latest version of [Microsoft.AVS.Management](https://www.powershellgallery.com/packages/Microsoft.AVS.Management) is a listed [dependency](https://docs.microsoft.com/en-us/nuget/reference/nuspec#dependencies) of the package.
> Please add any other additional dependencies as required.

## Versioning and Module manifest
AVS scripting modules are expected to follow [semver guidelines](https://semver.org/) when publishing a new version. Adhering to the guidelines will ensure that any automation built around the ARM resources representing the commandlets will keep working while benefiting from the patch fixes.

We also support following version suffixes:
- `-dev`, for example `1.0.0-dev`. Versions with this suffix are mapped to a subscription flag we only assign to vendors doing the testing on AVS.
- `-preview`. Versions with this suffix are mapped to `Microsoft.AVS/scriptingPreview` flag that any subscription owner can register for themselves.

Until there's an agreement with the AVS about the general availability, publish the package with `-dev` or `-preview` version suffix only. This would allow us to control the rollout and enable the consumer to opt-in into the experience before it is generally available.

To direct the customers to the information about the module make sure to include `ProjectUri` in the module manifest, supplying the address of the product support landing page designed for AVS customers. 


## Lifecycle commandlets
It is strongly recommended that the package includes the commandlets to manage and diagnose the entire lifecycle of the product.

| Cmdlet | Description |
| ------ | ----------- |
| preflight-install | Customer should be able to run this script prior to installation.  It should report on any current state that the install script will depend on.  If there are no errors it should be safe to install.|
| install | This script should call the pre-flight script and only continue if there are no errors in pre-flight.  The script should be able to skip install steps already completed.  Possibly from a previous install attempt.|
| preflight-upgrade | Customer should be able to run this script prior to upgrade.  It should report on any current state that the install script will depend on.  If there are no errors it should be safe to upgrade.|
| upgrade | This script should call the pre-flight script and only continue if there are no errors in pre-flight.  The script should be able to skip upgrade steps already completed.|
| rotate-credentials | If a service account was created during installation this commandlet should generate new password for the account.|
| preflight-uninstall | It should report on current state that the uninstall script will be working on.|
| uninstall | This script should be able to skip uninstall steps that were already completed. |
| diagnostics | This customer should be able to run this to get the most verbose state of the system. The intent is to have a tool to aid troubleshooting if install and/or uninstall do not run successfully|

## Scripts should be able to check if a step was already done and skip to next step

Things can go wrong and an initial installation attempt may partially complete before failure.   In the interest of reducing operational support, the script should be smart enough to know what state the previous attempt is in and be able to either redo the steps leading up to it or skip past them if it can.

## Uninstall script requirements

In the interest of reducing operational support, the script should be able to recover from any partially installed state - be smart enough to know what state an installation is in.  It may be installed successfully, failed on install, or failed on uninstall.  For any scenario the script should be smart enough to either redo the steps it already did or skip past them if they are not needed.

The uninstall script from the most recent package version should be able to uninstall any previous version. The portal UI will show only most recent versions and while the package might still be available for execution the user shouldn't be forced to use command line or template deployment to uninstall an older version.

## Script should not dump secrets to output

Any user credentials created for the 3rd party software installation, should be kept secret.   

# Suggested script vendor development flow
For the general script development the vendor should setup an on-prem vCenter. 
Then using a Linux dev box with PowerShell:
- Create a non-root user and login as that user
- Checkout your module repository
- Edit your module files
- Start `pwsh`
- Setup the context: login via PowerCLI and set the variables, like $VC_ADDRESS and $SSH_Sessions
- Import the module from your checked out directory
- Test
- Make changes to your module as necessary
- Restart the `pwsh` or remove and re-import your module
- Repeat

This should get the scripts to 99% ready for testing on AVS.

> Note: example of a script that sets up the context for your dev loop:
```ps
Set-PowerCLIConfiguration -InvalidCertificateAction:Ignore
$VC_ADDRESS = "10.0.0.2"
$PersistentSecrets = @{}
$VC_Credentials = Get-Credential
Connect-VIServer -Server $VC_ADDRESS -Credential $VC_Credentials
Connect-SsoAdminServer -Server $VC_ADDRESS -User $VC_Credentials.Username -Password $VC_Credentials.Password -SkipCertificateCheck
function sshLogin([PSCredential]$c) {
    $sshs = [System.Collections.Generic.Dictionary[string,object]]::new()
    $sftps = [System.Collections.Generic.Dictionary[string,object]]::new()
    foreach($h in Get-VMHost) {
        $sshs[$h.Name] = [Lazy[object]]::new([System.Func[object]] { New-SSHSession -ComputerName $h.Name -AcceptKey -Credential $c }.GetNewClosure())
        $sftps[$h.Name] = [Lazy[object]]::new([System.Func[object]] { New-SFTPSession -Computer $h.Name -AcceptKey -Credential $c }.GetNewClosure())
    }
    Set-Variable -Name SSH_Sessions -Value $sshs -Scope Global
    Set-Variable -Name SFTP_Sessions -Value $sftps -Scope Global
}
$ESX_Credentials = Get-Credential
sshLogin $ESX_Credentials
```

The final QA cycle would be:
- Publish the package with `-dev` version suffix
- Get on the Linux jumpbox connected to your SDDC vnet
- install docker and spin up an instance of this image: mcr.microsoft.com/powershell:7.4-alpine-3.17
- In the PowerShell container:
    - Install only your package from PS Gallery – this is to ensure that your package has correctly specified all the dependencies
    - Setup the context
    - Test

## Introducing breaking change in Microsoft management packages
For minor (non-breaking) changes we either let the build number increment or if we are introducing new functionality that we may need to referece we bump the minor version component.
For breaking changes please open a [RFC](/RFCs/template.md) PR and get the agreement of the stakeholders.

## Testing via Run Command and preparing for release
At this point you can tell us that it’s ready to be reviewed.
- We’ll review the package, import it into our private repository and list it for execution via Run Command/ARM API. Additional checklist may be required, work with your PM to determine.
- AVS "Customer 0" will evaluate the overall GA readiness
- Re-publish the package with `-preview` suffix to do a Private Preview with your customers.
- Re-publish the package w/o `-preview` suffix to make your package available to general public.
 
After this initial onboarding we require that the vendor sets up [CI testing](https://github.com/Azure/Microsoft.AVS.Management-FCT) that executes the commandlets via AVS SDK to make sure future packages pass the lifecycle test and to shield you from any possible changes on the AVS side. Promotion from `-preview` to generally available package will be conditional on the test report that shows that all commandlets perform as expected.

## FAQ
**Q**: Does the Run Command container have access to the Internet?</br>
**A**: Yes, the agent executing the commands is always connected to the Internet via AVS management network.

**Q**: Does the Run Command container have access to the customer's Azure VNet or resources?</br>
**A**: No, any access to customer resources other than VMware infrastructure of the SDDC would have to be scripted by the vendor.

**Q**: Does Run Command carry session state across invocations?</br>
**A**: No, with the exception of package-scoped secrets there is no support for preserving state across executions.

**Q**: Is there a way to invoke Run Command outside of the Azure portal?</br>
**A**: Yes, see [az vmware script-execution create](https://learn.microsoft.com/en-us/cli/azure/vmware/script-execution?view=azure-cli-latest#az-vmware-script-execution-create) documentation, or see the [C# sample](https://github.com/boumenot/Microsoft.AVS.Management/blob/main/samples/Program.cs) for an example using the Azure SDK.
