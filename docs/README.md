# AVS Run Command — Scripting Guidelines

Guidelines for Microsoft and third-party PowerShell developers building features for the [AVS Run Command](https://learn.microsoft.com/en-us/azure/azure-vmware/using-run-command) platform. Scripts run on **PowerShell 7.4+** with **VMware PowerCLI** in a **Linux container** environment (PSEdition `Core` only). AVS scripting is exposed as a standard [ARM resource](https://github.com/Azure/azure-rest-api-specs/blob/master/specification/vmware/resource-manager/Microsoft.AVS/stable/2021-06-01/vmware.json) — vendors should familiarize themselves with the capabilities available.

## Table of Contents

1. [Runtime Environment](#1-runtime-environment)
2. [Module Packaging](#2-module-packaging)
3. [Function Conventions](#3-function-conventions)
4. [Security](#4-security)
5. [Error Handling](#5-error-handling)
6. [Output and Streams](#6-output-and-streams)
7. [Lifecycle Cmdlets](#7-lifecycle-cmdlets)
8. [Development Workflow](#8-development-workflow)
9. [Release Process](#9-release-process)
10. [FAQ](#10-faq)

---

## 1. Runtime Environment

Microsoft imports vendor PowerShell packages, verifies conformance to AVS Run Command constraints, and makes them available for execution in AVS regions. The sections below describe what the platform provides before your script starts.

### 1.1 Pre-Established Sessions

Your script will **not** have access to the administrator password. Before execution begins, AVS establishes administrator-level sessions with vCenter, giving your code access to all vCenter APIs. The following logins are performed automatically:

- PowerCLI's [Connect-VIServer](https://developer.vmware.com/docs/powercli/latest/vmware.vimautomation.core/commands/connect-viserver/#Default)
- VMware's [Connect-SsoAdminServer](https://github.com/vmware/PowerCLI-Example-Scripts/tree/master/Modules/VMware.vSphere.SsoAdmin)
- VMware's [Connect-VcenterServerMOB](https://github.com/vmware/PowerCLI-Example-Scripts/tree/master/Modules/VMware.vSphere.SsoAdmin)

> **Do not** call any of these in your scripts — see [Session Management](#41-session-management).

### 1.2 Environment Variables

AVS exposes the following PowerShell variables at runtime:

| Variable | Description | Notes |
|----------|-------------|-------|
| `$VC_ADDRESS` | IP address of vCenter | Use `"vc.$SddcDnsSuffix"` for HTTPS requests instead |
| `$SddcDnsSuffix` | Domain suffix of the SDDC | |
| `$SddcResourceId` | ARM ResourceId of the SDDC | e.g., `"/subscriptions/.../providers/Microsoft.AVS/privateClouds/myCloud"` |
| `$AadAuthority` | Azure Active Directory address in this Azure Cloud | e.g., `"https://login.microsoftonline.com/"` |
| `$PersistentSecrets` | Hashtable for keeping secrets across executions | See [Persistent Secrets](#13-persistent-secrets) |
| `$SSH_Sessions` | Dictionary of hostname → [Lazy](https://docs.microsoft.com/en-us/dotnet/api/system.lazy-1?view=netcore-2.1) [SSH session](https://github.com/darkoperator/Posh-SSH/blob/master/docs/New-SSHSession.md) | `Invoke-SSHCommand -Command "uname -a" -SSHSession $SSH_Sessions["esx.host.fqdn"].Value` — use key `"VC"` for SSH to vCenter |
| `$SFTP_Sessions` | Dictionary of hostname → [Lazy](https://docs.microsoft.com/en-us/dotnet/api/system.lazy-1?view=netcore-2.1) [SFTP session](https://github.com/darkoperator/Posh-SSH/blob/master/docs/New-SFTPSession.md) | `New-SFTPItem -ItemType Directory -Path "/tmp/zzz" -SFTPSession $SFTP_Sessions["esx.host.fqdn"].Value` — use key `"VC"` for SFTP to vCenter |
| `$MOB_Connection` | Connection object from `Connect-VcenterServerMOB` | Requires `Microsoft.AVS.Management` ≥ v7.0.170 as a dependency |

### 1.3 Persistent Secrets

- Secrets are stored in Azure Key Vault, isolated by package name, shared across all versions of your package, and made available to each of your package's scripts.
- Delete a secret by setting its hashtable entry to an empty string or `$null`.
- Secret names must conform to [Key Vault naming constraints](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?tabs=HTTP#uri-parameters).
- Secrets are only persisted on **successful** cmdlet termination — any unhandled exception prevents persistence.

```powershell
# Store a secret
$PersistentSecrets['ManagementAppliancePassword'] = $secureValue

# Delete a secret
$PersistentSecrets['ManagementAppliancePassword'] = $null
```

### 1.4 Temporary Storage

The script's working directory is temporary with approximately **25 GB** of space available. This environment, including any files created, is torn down after script execution completes.

### 1.5 Network Connectivity

Network access differs between AVS Gen 1 and Gen 2 SDDCs:

| Capability | Gen 1 | Gen 2 |
|------------|-------|-------|
| Internet access | Connected via AVS management network | HTTPS connectivity to common Azure endpoints; general Internet connectivity provided by the customer network |
| Customer Azure VNet access | **No** — access to customer resources other than VMware infrastructure must be scripted by the vendor | **Yes** — the Run Command agent has access to the customer's Azure network |

### 1.6 Script Execution Model

- **Serialized execution**: scripts execute one at a time for safety.
- **SDDC state**: executing against an SDDC in the `Updating` state results in an error. A script can set the SDDC state to `Updating` via `AVSAttribute` (see [Required Attributes](#31-required-attributes)).
- **Timeout**: default is 30 minutes; maximum is 60 minutes. Authors can override this per-cmdlet via `AVSAttribute`. AVS terminates scripts that exceed their timeout.
- **No child processes**: Use PowerShell-native facilities.
- **Review**: AVS reviews all scripts before making them available. Script authors are expected to provide support during this process.

---

## 2. Module Packaging

Scripts must be packaged as PowerShell modules and published as NuGet packages. AVS uses a private package repository for production; publish to [PowerShell Gallery](https://www.powershellgallery.com/) for testing and review.

### 2.1 Module Manifest

The module manifest (`.psd1`) must include:

| Field | Value |
|-------|-------|
| `PowerShellVersion` | `'7.4'` |
| `FunctionsToExport` | Explicit list of public functions |
| `ProjectUri` | Product support landing page for AVS customers |

### 2.2 Dependencies

- Vendor packages **must** list the latest version of [Microsoft.AVS.Management](https://www.powershellgallery.com/packages/Microsoft.AVS.Management) as a [dependency](https://docs.microsoft.com/en-us/nuget/reference/nuspec#dependencies).
- Add any other required modules (e.g., `VMware.VimAutomation.Core`).

> **IMPORTANT**: Test your package using a Linux [PowerShell container](https://hub.docker.com/_/microsoft-powershell), connecting to your on-prem datacenter. Install **only** your package from PS Gallery to verify all dependencies are correctly declared.

### 2.3 Versioning

Follow [semver guidelines](https://semver.org/) when publishing. Supported version suffixes:

| Suffix | Purpose | Access Control |
|--------|---------|----------------|
| `-dev` | Vendor testing | Mapped to a subscription flag assigned only to testing vendors |
| `-preview` | Opt-in preview | Mapped to `Microsoft.AVS/scriptingPreview` flag; any subscription owner can self-register |
| *(none)* | General availability | Available to all customers |

Until there is an agreement with AVS about general availability, publish **only** with `-dev` or `-preview` suffix.

#### API Version References

To avoid breakages when AVS deprecates specific package versions, API consumers should reference packages using the `Major.*` pattern instead of a specific version.

For example, if the current version of `Microsoft.AVS.VMFS` is `1.0.151`, API calls should use `Microsoft.AVS.VMFS@1.*`.

---

## 3. Function Conventions

### 3.1 Required Attributes

Every exported function available via AVS Run Command **must** have:

1. **`[CmdletBinding()]`** attribute
2. **`[AVSAttribute(timeoutMinutes)]`** — max 60, default 30
3. All inputs as **named parameters** in a `param()` block

```powershell
function Set-Example {
    <#
    .DESCRIPTION
        Applies example configuration to all hosts in the specified
        vSphere cluster. Validates that the cluster exists before
        making any changes.
    .PARAMETER ClusterName
        Name of the vSphere cluster to configure.
    #>
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName
    )
    # ...
}
```

`AVSAttribute` properties:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Timeout` | `int` (minutes) | 30 | Constructor argument. Maximum 60 minutes. |
| `UpdatesSDDC` | `bool` | `$false` | Set to `$true` if the function changes SDDC state. |
| `AutomationOnly` | `bool` | `$false` | Set to `$true` for functions callable only via automation (not the portal). |

### 3.2 Parameter Types

Only the following types are natively supported — all others are passed as strings and must support automatic conversion from `String`:

| Type | Notes |
|------|-------|
| `String` | Must be [sanitized](#43-input-sanitization) if intended for command-line formatting |
| `Double` | |
| `Boolean` | |
| `Int32` | |
| `PSCredential` | Encrypted in-flight and at rest; never echoed back |
| `SecureString` | Encrypted in-flight and at rest; never echoed back |

### 3.3 Parameter Rules

- **No dynamic or conditional parameters.** If the value of one parameter affects the optionality or meaning of another, split the cmdlet into two or more cmdlets — each tailored for a specific use case. Cmdlets are statically analyzed and all parameters are presented for the user to fill in.
- Optional parameters are supported.
- Functions and parameters must have user-friendly descriptions using standard PowerShell facilities.

### 3.4 Naming

All function and parameter names must follow PowerShell [naming guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/required-development-guidelines?view=powershell-7.3#use-only-approved-verbs-rd01) (`Verb-Noun` format with approved verbs).

### 3.5 Comment-Based Help

Every exported function **must** include comment-based help with at least:

- `.SYNOPSIS` — brief one-line description, or
- `.DESCRIPTION` — detailed description of behavior (if .SYNOPSIS is omitted)
- `.PARAMETER` — one entry per parameter

See the example in [Required Attributes](#31-required-attributes) above.

---

## 4. Security

### 4.1 Session Management

**Never** call `Connect-VIServer`, `Connect-SsoAdminServer`, or `Connect-VcenterServerMOB` in your scripts. AVS establishes these sessions automatically with administrator-level privileges before your code runs (see [Pre-Established Sessions](#11-pre-established-sessions)). Scripts that attempt their own logins will not be allowed to run.

### 4.2 Privilege Restrictions

**Never** elevate privileges for the `cloudadmins` role. The script is already logged in with administrator privileges and does not need `cloudadmins` elevation. Elevating `cloudadmins` would give elevated access to anyone using that role, leading to unintended consequences.

**Never** use `cloudadmin` as the service account for installed software. Instead:

1. Create a separate vCenter user and role during installation.
2. Use the `cloudadmins` role as a base — duplicate it, then add the necessary elevated privileges.
3. The new role's privileges will be reviewed by Microsoft.
4. Always add the new account to the `CloudAdmins` SSO group.

### 4.3 Input Sanitization

`String` parameters do not pose a code injection risk when passed directly as cmdlet parameters — PowerShell parameter binding does not execute string values as code. However, sanitization is still required in two scenarios:

1. **Wildcard injection** — many PowerShell cmdlets (e.g., `Get-Cluster -Name`, `Get-Tag -Name`, `Get-SpbmStoragePolicy -Name`) interpret wildcard characters in `-Name` parameters. A user-supplied `*` or `?` could match unintended objects. Sanitize before any cmdlet call where wildcards are not desired or could cause unexpected matches.

2. **Script generation** — if `String` parameters are used to [build or generate scripts](https://learn.microsoft.com/en-us/mem/configmgr/apps/deploy-use/learn-script-security#powershell-parameters-security), they must be sanitized to prevent code injection.

Available functions (provided by `Microsoft.AVS.Management`):

- **`Limit-WildcardsandCodeInjectionCharacters`** — strips wildcard and injection characters (`*`, `?`, `[`, `]`, `;`, `|`, `\`, `$_`, `{`, `}`).

  ```powershell
  $ClusterName = Limit-WildcardsandCodeInjectionCharacters -String $ClusterName
  $Cluster = Get-Cluster -Name $ClusterName   # safe from wildcard matching
  ```

- **`Test-AVSProtectedObjectName`** — validates names against a list of 60+ protected vSAN policies, storage policies, system roles, and NSX roles. Call this before creating or deleting any policies, roles, or users.

  ```powershell
  Test-AVSProtectedObjectName -Name $PolicyName  # throws if name is protected
  ```

### 4.4 Credential Handling

- Use `PSCredential` and `SecureString` parameter types for any secrets or credentials — these are encrypted in-flight and at rest and are never echoed back to the user.
- **Never** log or dump secrets to any output stream.
- Use `$PersistentSecrets` for credentials that need to survive across executions (see [Persistent Secrets](#13-persistent-secrets)).

### 4.5 Appliance Deployments

When deploying an appliance that requires service credentials with privileges above the `cloudadmins` role, vendors must ensure credentials are never exposed — not in-flight and not at rest.

#### Secure Folder API

The `[AVSSecureFolder]` class (from `Microsoft.AVS.Management`) manages vSphere folders with restricted permissions:

| Method | Description |
|--------|-------------|
| `[AVSSecureFolder]::Root()` | Returns (or creates) the vendor root folder (`vm/AVS-vendor-folders`) with restricted permissions: `scripting` user gets Admin role, `CloudAdmins` gets ReadOnly |
| `[AVSSecureFolder]::GetOrCreate($name)` | Creates a named subfolder under the vendor root, inheriting the restricted permission model |
| `[AVSSecureFolder]::Secure($folder)` | Applies the restricted permission model to all objects in an existing folder |

#### Appliance Security Requirements

- The appliance user must not have root access or direct access to the storage/file system where credentials are stored.
- Deploy the appliance in a secure folder (`[AVSSecureFolder]::GetOrCreate()`), then re-secure with `[AVSSecureFolder]::Secure()` after deployment.
- Pass credentials as OVA properties to the appliance, including during credential rotation.
- The appliance must enforce HTTPS with host authentication when communicating with vCenter.
- Credentials must never be logged; no diagnostic bundle may include credentials.
- The vendor must provide cmdlets to rotate the service account password and to perform appliance updates including security patches.
- Use `$PersistentSecrets` if scripts need access to credentials later.

#### Information Protection

- The appliance may not expose VMware logs directly to the customer. All logs and diagnostics from VMware infrastructure must go through AVS, where they are filtered for sensitive information.
- AVS provides syslog forwarding to make relevant logs available in Azure.

---

## 5. Error Handling

### 5.1 Fail-Fast Validation

Validate all prerequisites **before** making any changes. Fail early with a clear error if something is missing:

```powershell
$Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
if (-not $Cluster) {
    throw "Cluster '$ClusterName' not found."
}
```

### 5.2 Rollback on Partial Failure

When a function modifies multiple resources (e.g., configuring each host in a cluster), track changes as you go so you can roll back on failure. Only undo changes made in the **current run** — preserve pre-existing state.

Reference implementation: `Set-VmfsIscsi` in `Microsoft.AVS.VMFS/Microsoft.AVS.VMFS.psm1`:

```powershell
$ConfiguredHosts = @()
foreach ($VMHost in $VMHosts) {
    try {
        # Make the change ...
        $ConfiguredHosts += @{ VMHost = $VMHost; TargetAdded = $true }
    }
    catch {
        $FailedHost = $VMHost.Name
        # Rollback only what THIS run changed
        foreach ($Entry in $ConfiguredHosts) {
            if ($Entry.TargetAdded) {
                Remove-IScsiHbaTarget -Target $Target -Confirm:$false -ErrorAction Stop
                Write-Warning "Rolled back iSCSI target on host $($Entry.VMHost.Name)."
            }
        }
        throw "Failed to configure iSCSI on host $FailedHost. " +
              "Changes on previously configured hosts have been rolled back. " +
              "Error: $($_.Exception.Message)"
    }
}
```

### 5.3 Error Messages

- Use `-ErrorAction Stop` for fatal errors.
- Always include the failing entity in error messages for troubleshooting context:

```powershell
throw "Failed to set storage policy on cluster '$ClusterName': $($_.Exception.Message)"
```

---

## 6. Output and Streams

### 6.1 PowerShell Streams

The execution pipeline supports four streams:

| Stream | Usage | Cmdlet |
|--------|-------|--------|
| Output | Results returned to the caller | Implicit (any unassigned expression) |
| Information | User-facing confirmations | `Write-Host` |
| Warning | Cautions and non-fatal issues | `Write-Warning` |
| Error | Failures | `Write-Error` + `throw` |

Stream content is always stored as strings. Objects emitted into streams should be primitives (`String`, `Int`, etc.), `HashTable`, or explicitly converted to string — otherwise they may fail to deserialize and won't be captured.

### 6.2 Suppressing Stray Output

In PowerShell, any expression that produces a value (e.g., `Stop-VM`, `$true`) emits that value into the Output stream unless captured in a variable or piped to `Out-Null`. Stray output can disrupt other streams. Be intentional about every expression:

```powershell
$null = Stop-VM -VM $vm -Confirm:$false   # capture to suppress
Set-VMHost -VMHost $h -State Maintenance | Out-Null   # pipe to suppress
```

### 6.3 NamedOutputs

On successful execution, a script can return structured key/value pairs to the caller via a `$NamedOutputs` hashtable. This object appears in the [ARM resource properties](https://github.com/Azure/azure-rest-api-specs/blob/master/specification/vmware/resource-manager/Microsoft.AVS/stable/2021-06-01/vmware.json#L6921).

```powershell
$NamedOutputs = @{}
$NamedOutputs['k1'] = 'v1'
$NamedOutputs['k2'] = 2  # values are converted to string — convert complex types yourself

Set-Variable -Name NamedOutputs -Value $NamedOutputs -Scope Global
```

> **IMPORTANT**: The total size of the `NamedOutputs` collection must not exceed **32 KB**.

---

## 7. Lifecycle Cmdlets

It is strongly recommended that packages include cmdlets covering the complete product lifecycle. The table below describes the expected categories — vendors should choose their own `Verb-Noun` names following [PowerShell naming guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/required-development-guidelines?view=powershell-7.3#use-only-approved-verbs-rd01).

| Category | Description | Example Name |
|----------|-------------|--------------|
| preflight-install | Run before installation. Reports current state and prerequisites. If no errors, it is safe to install. | `Test-ProductInstallPreFlight` |
| install | Calls preflight first. Installs the product, skipping steps already completed from a previous attempt. | `Install-Product` |
| preflight-upgrade | Run before upgrade. Reports current state and prerequisites. If no errors, it is safe to upgrade. | `Test-ProductUpgradePreFlight` |
| upgrade | Calls preflight first. Upgrades the product, skipping steps already completed. | `Update-Product` |
| rotate-credentials | Generates a new password for the service account created during installation. | `Set-ProductCredentialRotation` |
| preflight-uninstall | Reports the current state that the uninstall will work on. | `Test-ProductUninstallPreFlight` |
| uninstall | Removes the product, skipping steps already completed. | `Uninstall-Product` |
| diagnostics | Returns verbose system state for troubleshooting failed installs or uninstalls. | `Get-ProductDiagnostics` |

### 7.1 Idempotency

Scripts must detect partially completed state and skip past steps that are already done. An initial installation attempt may partially complete before failure — the script should be resilient enough to resume from any intermediate state without manual intervention.

### 7.2 Uninstall Requirements

- The uninstall script must recover from **any** partially installed state: successful install, failed install, or failed uninstall.
- The uninstall script from the **most recent** package version must be able to uninstall any previous version. The portal UI shows only recent versions, and users should not need CLI or template deployment to uninstall an older version.

---

## 8. Development Workflow

### 8.1 Local Development Loop

Set up an on-prem vCenter, then develop on a Linux machine with PowerShell:

1. Create a non-root user and log in as that user.
2. Check out your module repository.
3. Edit your module files.
4. Start `pwsh`.
5. Set up context: log in via PowerCLI and set the runtime variables (`$VC_ADDRESS`, `$SSH_Sessions`, etc.).
6. Import your module from the checked-out directory.
7. Test.
8. Make changes, then restart `pwsh` (or `Remove-Module` / `Import-Module`) and repeat.

This gets scripts to ~99% ready for testing on AVS.

<details>
<summary>Example context setup script</summary>

```powershell
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

</details>

### 8.2 Testing in a Linux Container

The final QA cycle before requesting AVS review:

1. Publish the package with `-dev` version suffix.
2. Get on a Linux jumpbox connected to your SDDC VNet.
3. Spin up a PowerShell container: `mcr.microsoft.com/powershell:7.4-alpine-3.17`
4. In the container:
   - Install **only** your package from PS Gallery — this verifies all dependencies are correctly declared.
   - Set up the context.
   - Test all lifecycle cmdlets.

### 8.3 CI Testing

After initial onboarding, vendors must set up [CI testing](https://github.com/Azure/Microsoft.AVS.Management-FCT) that executes cmdlets via the AVS SDK. This ensures future package versions pass lifecycle tests and protects against platform-side changes.

Promotion from `-preview` to generally available status is conditional on a test report showing all cmdlets perform as expected.

---

## 9. Release Process

### 9.1 Onboarding Flow

1. **Develop and test locally** using the workflow described in [Development Workflow](#8-development-workflow).
2. **Publish with `-dev` suffix** and notify AVS that the package is ready for review.
3. **AVS review**: the package is imported into the private repository and listed for execution via Run Command / ARM API. Work with your PM to determine any additional checklist items.
4. **Customer 0 evaluation**: AVS evaluates GA readiness.
5. **Publish with `-preview` suffix** to run a Private Preview with your customers.
6. **Publish without suffix** to make the package generally available.

### 9.2 Breaking Changes

For **non-breaking** changes, increment the build number. For new functionality that needs to be referenced, bump the minor version.

For **breaking** changes to Microsoft management packages, open an [RFC](/RFCs/template.md) PR and get agreement from stakeholders before proceeding.

### 9.3 ARM API Versioning

To avoid client-side breakages when AVS deprecates specific package versions, it is strongly recommended that API invocations use the `Major.*` version pattern instead of referencing a specific version.

```
# Instead of:
Microsoft.AVS.VMFS@1.0.151

# Use:
Microsoft.AVS.VMFS@1.*
```

---

## 10. FAQ

**Q: Does the Run Command container have access to the Internet?**
**A:** On Gen 1 SDDCs, the agent is always connected to the Internet via the AVS management network. On Gen 2 SDDCs, HTTPS connectivity to common Azure endpoints is provided, but general Internet connectivity must be provided by the customer network.

**Q: Does the Run Command container have access to the customer's Azure VNet or resources?**
**A:** On Gen 1, no — any access to customer resources other than the SDDC's VMware infrastructure must be scripted by the vendor. On Gen 2, yes — the Run Command agent has access to the customer's Azure network.

**Q: Does Run Command carry session state across invocations?**
**A:** No. With the exception of package-scoped [persistent secrets](#13-persistent-secrets), there is no support for preserving state across executions.

**Q: Is there a way to invoke Run Command outside of the Azure portal?**
**A:** Yes. See the [az vmware script-execution create](https://learn.microsoft.com/en-us/cli/azure/vmware/script-execution?view=azure-cli-latest#az-vmware-script-execution-create) CLI documentation, or see the [C# sample](https://github.com/boumenot/Microsoft.AVS.Management/blob/main/samples/Program.cs) for an example using the Azure SDK.
