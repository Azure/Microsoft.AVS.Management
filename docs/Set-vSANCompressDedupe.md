# Set-vSANCompressDedupe ESA Support

> **ADO Work Item:** Change Set-vSANCompressDedupe to work with ESA
> **Branch:** kguntaka/37352107
> **Last Updated:** 2026-04-07

---

## 1. Objective

Update the `Set-vSANCompressDedupe` Run Command to detect vSAN ESA (Express Storage Architecture) clusters and handle them properly, instead of attempting unsupported operations.

### The Problem

- The current `Set-vSANCompressDedupe` function calls `Set-VsanClusterConfiguration` to toggle compression and deduplication at the cluster level.
- This works for **vSAN OSA** (Original Storage Architecture) — the older architecture.
- For **vSAN ESA**, compression and deduplication are **not managed at the cluster level**. They are handled automatically via **Storage Policies**, and the cluster-level toggle does not apply.
- Running the current command on an ESA cluster either fails silently, throws an unclear error, or produces unexpected behavior.

### What ESA Changes

| Feature | vSAN OSA (Original) | vSAN ESA (Express) |
|---------|---------------------|-------------------|
| Compression | Cluster-level toggle via `Set-VsanClusterConfiguration` | Always enabled, managed via Storage Policies |
| Deduplication | Cluster-level toggle (requires compression) | Managed via Storage Policies |
| How to configure | Run Command / PowerCLI at cluster level | Storage Policy assignment on VMs/datastores |

### Goal

When a user runs `Set-vSANCompressDedupe` on an ESA cluster:
1. **Detect** that the cluster is ESA
2. **Do NOT** call `Set-VsanClusterConfiguration` (it won't work correctly)
3. **Return a clear error message** explaining that ESA clusters manage compression/deduplication via Storage Policies
4. **Fail gracefully** — don't make any changes

When the cluster is OSA, the function should continue working exactly as it does today.

---

## 2. Current Function

**File:** `Microsoft.AVS.Management/Microsoft.AVS.Management.psm1` (line ~926)

**Current behavior:**
- Takes `ClustersToChange` (comma-separated string), `Deduplication` (bool), `Compression` (bool)
- Loops through each cluster
- Calls `Set-VsanClusterConfiguration` with `-SpaceEfficiencyEnabled` or `-SpaceCompressionEnabled`
- No ESA detection — blindly applies to any cluster type

**Current issues:**
- No `[CmdletBinding()]` attribute (required by AVS conventions)
- No input sanitization (`Limit-WildcardsandCodeInjectionCharacters`)
- Comment-based help is outside the function (should be inside)
- No error handling (`-ErrorAction Stop`, try/catch)
- No ESA detection

---

## 3. Implementation Plan

### Step 1: Add ESA Detection
- Use `Get-VsanClusterConfiguration` to check if the cluster uses ESA architecture
- The `VsanClusterConfiguration` object should have a property indicating ESA (e.g., `VsanDiskClaimMode`, architecture type, or similar)
- **Need to verify:** exact PowerCLI property name for ESA detection on a real cluster

### Step 2: Add ESA Guard
- If ESA detected: throw a clear error message and skip that cluster
- If OSA: proceed with existing logic


### Step 3: Add Pester Tests
- Mock `Get-VsanClusterConfiguration` to return ESA and OSA configs
- Test that ESA clusters get rejected with proper error
- Test that OSA clusters still work
- Test parameter validation and AVSAttribute

---

## 4. Files to Modify

| File | Change |
|------|--------|
| `Microsoft.AVS.Management/Microsoft.AVS.Management.psm1` | Update `Set-vSANCompressDedupe` function |
| `tests/Microsoft.AVS.Management.Tests.ps1` | Add Pester tests |

---

## 5. Implementation Log

| Date | Action | Details |
|------|--------|---------|
| 2026-04-07 | Research complete | Current function has no ESA detection. No existing tests. Function also missing CmdletBinding and input sanitization. |
| 2026-04-07 | ESA detection implemented | Added `Get-VsanClusterConfiguration` check for `VsanDiskClaimMode == FullyAutomated` (ESA). ESA clusters are skipped with `Write-Warning`, OSA clusters proceed as before. After loop, throws if any clusters were skipped. ~9 new lines, no existing lines modified. |
| | | |

---

## 6. Design Decisions

### 1. ESA Detection — How to detect ESA vs OSA

**Approach:** Use `Get-VsanClusterConfiguration` and check the `VsanDiskClaimMode` property.

- `VsanDiskClaimMode = "Manual"` → **OSA** (Original Storage Architecture)
- `VsanDiskClaimMode = "FullyAutomated"` → **ESA** (Express Storage Architecture)

> **Note:** This is the most commonly documented PowerCLI property for ESA detection. Must be verified on a real ESA cluster. Alternative properties to check if this doesn't work: `IsEsaEnabled`, `StorageArchitecture`, or querying via `Get-VsanView`.

**Simple rule:** Detect architecture first → decide → proceed or skip.

### 2. Mixed-Cluster Scenarios — Handle per cluster, not all-or-nothing

When a user passes multiple clusters (e.g., `"cluster-1,cluster-2"`) and one is ESA, one is OSA:

| Cluster | Type | Action |
|---------|------|--------|
| cluster-1 | OSA | Proceed — apply compression/deduplication changes |
| cluster-2 | ESA | Skip — log a clear warning message, continue to next cluster |

**Why:** More user-friendly. Doesn't block valid OSA clusters just because one ESA cluster is in the list. Matches how admins expect tooling to behave.

**After the loop:** If ANY clusters were skipped, throw an error summarizing which clusters were ESA and skipped — so the Run Command reports partial failure rather than silent success.

### 3. Logging — Always log skipped clusters

For every cluster processed, log:

| Field | Example |
|-------|---------|
| Cluster name | `cluster-2` |
| Architecture | `ESA` |
| Action taken | `Skipped` |
| Reason | `Compression/deduplication is managed via Storage Policies on ESA clusters` |

Use `Write-Host` for processed clusters, `Write-Warning` for skipped ESA clusters.

---

## 7. References

- ADO Work Item: Change Set-vSANCompressDedupe to work with ESA
- [VMware vSAN ESA Overview](https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/GUID-18F531E9-FF08-49F5-9879-8E46583D4C70.html)
- [vSAN ESA vs OSA Differences](https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/GUID-4BE5D935-B8CF-4F9C-B8AC-3E641B904498.html)