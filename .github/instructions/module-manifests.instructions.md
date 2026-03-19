---
description: "Use when creating or editing PowerShell module manifests (.psd1) for AVS packages. Covers versioning, dependencies, export lists, and metadata."
applyTo: "**/*.psd1"
---
# Module Manifest Conventions

## Versioning

Follow [semver](https://semver.org/). Use suffixes for pre-release:
- `-dev` — vendor testing only (mapped to subscription flag)
- `-preview` — opt-in preview (`Microsoft.AVS/scriptingPreview` flag)

API consumers should reference packages as `Module@Major.*` (e.g., `Microsoft.AVS.VMFS@1.*`).

## Required Fields

- `PowerShellVersion = '7.4'` — minimum supported version
- `CompatiblePSEditions = @('Core')` — Linux container environment
- `FunctionsToExport` — list all public functions explicitly, never use `'*'`
- `ProjectUri` — product support landing page for AVS customers

## Dependencies

- Vendor packages **must** list `Microsoft.AVS.Management` as a dependency
- Add any other required modules (e.g., `VMware.VimAutomation.Core`)
- Pin specific versions when backward compatibility is not guaranteed (see CDR module)

## Example

```powershell
@{
    ModuleVersion     = '1.0.0'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')
    GUID              = '<generate-new-guid>'
    Author            = 'Vendor Name'
    Description       = 'AVS Run Command package for ...'
    RootModule        = 'ModuleName.psm1'
    FunctionsToExport = @('Install-Product', 'Remove-Product', 'Test-ProductPreFlight')
    RequiredModules   = @(@{ ModuleName = 'Microsoft.AVS.Management'; ModuleVersion = '9.0.0' })
    PrivateData       = @{ PSData = @{ ProjectUri = 'https://support.vendor.com/avs' } }
}
```
