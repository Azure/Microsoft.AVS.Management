---
description: "Use when editing CDR redirect maps, dependency resolution JSON files in Microsoft.AVS.CDR/maps/, or working with the Conservative Dependency Resolver module."
---
# CDR Redirect Map Conventions

CDR (Conservative Dependency Resolver) pins PowerCLI transitive dependencies to known-good versions, working around backward-compatibility breaks (e.g., PowerCLI 13.4 breaking 13.3).

## Map Location & Naming

Maps live in `Microsoft.AVS.CDR/maps/` and are named by the package they resolve for:
```
Microsoft.AVS.Management@9.json   # For Management v9.x
Microsoft.AVS.Management@8.json   # For Management v8.x
```

## JSON Structure

Keys are module names (optionally with `@Version`), values are pinned version strings:

```json
{
    "VMware.VimAutomation.Common": "13.3.0.24145081",
    "VMware.VimAutomation.Core@13.3.0.24145081": "13.3.0.24145081"
}
```

### Key Formats
- `ModuleName` — applies to any version of that module
- `ModuleName@Version` — applies only when that specific version is requested

### Resolution Rules
- Version matching cascades: `Name@9.0.1` → `Name@9.0` → `Name@9` → `Name`
- Diamond dependencies: grouped by module name, highest semver wins
- Prerelease versions sort below release versions
- Cycles are detected and warned about
