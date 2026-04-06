# AVS Run Command — Project Guidelines

Azure VMware Solution (AVS) PowerShell toolkit for administering private VMware datacenters on Azure via the [AVS Run Command](https://learn.microsoft.com/en-us/azure/azure-vmware/using-run-command) platform. Scripts run on PowerShell 7.4+ with VMware PowerCLI in a Linux container environment.

## Architecture

| Module | Role |
|--------|------|
| `Microsoft.AVS.Management` | Core: storage policies, vSAN, encryption, DRS, utility classes |
| `Microsoft.AVS.CDR` | Conservative Dependency Resolver — pins PowerCLI transitive deps to known-good versions |
| `Microsoft.AVS.NFS` | NFS datastore mount/unmount |
| `Microsoft.AVS.VMFS` | iSCSI + VMFS datastore lifecycle |

Vendor packages must list `Microsoft.AVS.Management` as a dependency.

## Key Guidelines

Full scripting guidelines: [docs/README.md](../docs/README.md). PR checklist: [CONTRIBUTING.md](../CONTRIBUTING.md).

### Function Conventions

- Every exported function requires `[CmdletBinding()]` and `[AVSAttribute(timeoutMinutes)]` (max 60, default 30).
- Use `Verb-Noun` naming per [PowerShell guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/required-development-guidelines?view=powershell-7.3).
- Supported parameter types: `String`, `Double`, `Boolean`, `Int32`, `PSCredential`, `SecureString`.
- No dynamic or conditional parameters — split into separate cmdlets instead.
- No child processes — find PowerShell-native alternatives.

### Security (Critical)

- **Never** call `Connect-VIServer` or `Connect-SsoAdminServer` in scripts — AVS pre-establishes admin sessions.
- **Never** elevate `cloudadmins` privileges.
- Sanitize all `String` parameters with `Limit-WildcardsandCodeInjectionCharacters` before use.
- Validate names against `Test-AVSProtectedObjectName` before creating/deleting policies or roles.
- Use `SecureString` / `PSCredential` for any secrets or credentials — never log them.
- Use `[AVSSecureFolder]` for appliance deployments requiring restricted access.

### Error Handling

- Validate all prerequisites before making changes (fail early).
- Track changes for rollback on partial failure (see `Set-VmfsIscsi` in Microsoft.AVS.VMFS for the pattern).
- Use `-ErrorAction Stop` for fatal errors; include context in error messages.
- Wrap error messages with the failing entity: `"Failed to configure iSCSI on host $FailedHost: $($_.Exception.Message)"`

### Output Streams

- `Write-Host` for user-facing confirmations; `Write-Warning` for cautions; `Write-Error` + `throw` for failures.
- Suppress unintended output with `Out-Null` or variable capture — stray output disrupts other streams.
- Return structured results via `$NamedOutputs` hashtable (max 32KB), set with `Set-Variable -Name NamedOutputs -Scope Global`.

### Runtime Environment

Pre-established by AVS before script execution:

| Variable | Purpose |
|----------|---------|
| `$VC_ADDRESS` | vCenter IP (use `"vc.$SddcDnsSuffix"` for HTTPS instead) |
| `$SddcDnsSuffix` | Domain suffix of the SDDC |
| `$SddcResourceId` | ARM ResourceId of the SDDC |
| `$PersistentSecrets` | Hashtable for secrets across executions (stored in KeyVault) |
| `$SSH_Sessions` / `$SFTP_Sessions` | Lazy dictionaries of hostname → SSH/SFTP sessions |
| `$MOB_Connection` | vCenter MOB connection (requires Management v7.0.170+) |

## Build & Test

```bash
# Run Pester tests
Invoke-Pester -Path ./tests/

# Run PSScriptAnalyzer (CI uses PSGallery ruleset)
Invoke-ScriptAnalyzer -Path ./ -Recurse -Settings PSGallery
```

Test packages in a Linux [PowerShell container](https://hub.docker.com/_/microsoft-powershell) connecting to your datacenter.

## Versioning

Follow [semver](https://semver.org/). Use `-dev` suffix for vendor testing, `-preview` for opt-in preview. API consumers should reference packages as `Module@Major.*` (e.g., `Microsoft.AVS.VMFS@1.*`).
