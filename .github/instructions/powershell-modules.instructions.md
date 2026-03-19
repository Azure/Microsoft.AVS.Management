---
description: "Use when creating or editing PowerShell module files (.psm1) for AVS Run Command packages. Covers module structure, exported function requirements, AVSAttribute, and parameter conventions."
applyTo: "**/*.psm1"
---
# PowerShell Module Conventions

## Module Structure

Dot-source utility files at the top, then define functions, then export:

```powershell
. "$PSScriptRoot/Classes.ps1"
. "$PSScriptRoot/Utils.ps1"

function Verb-Noun { ... }

Export-ModuleMember -Function Verb-Noun
```

See [Microsoft.AVS.Management.psm1](../../Microsoft.AVS.Management/Microsoft.AVS.Management.psm1) as the canonical example.

## Exported Function Requirements

If an exported function is to be available via AVS Run Command it **must** have:
1. `[CmdletBinding()]` attribute
2. `[AVSAttribute(timeoutMinutes)]` — max 60, default 30
3. All inputs as named parameters in a `param()` block
4. Comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`)

```powershell
function Set-Example {
    <#
    .SYNOPSIS Configures example setting on a cluster.
    .PARAMETER ClusterName Name of the vSphere cluster.
    #>
    [CmdletBinding()]
    [AVSAttribute(30, UpdatesSDDC = $false)]
    param(
        [Parameter(Mandatory = $true)][string]$ClusterName
    )
    # ...
}
```

Set `UpdatesSDDC = $true` if the function changes SDDC state. Set `AutomationOnly = $true` for functions only callable via automation (not portal).

## Parameter Types

Only these types are supported — all others are passed as strings:
- `String`, `Double`, `Boolean`, `Int32`
- `PSCredential`, `SecureString` (for secrets — encrypted in-flight and at rest)

## Parameter Rules

- **No dynamic or conditional parameters.** If one parameter changes the meaning of another, split into separate cmdlets.
- **Validate names** with `Test-AVSProtectedObjectName` before creating or deleting policies, roles, or users.
