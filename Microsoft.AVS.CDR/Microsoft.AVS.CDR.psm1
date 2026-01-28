$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Default redirect map - keyed on dependency name@version or name only
# falls back to name-only for missing versions
$script:defaultRedirectMap = @{
}

# Cache for loaded module-specific redirect maps
$script:moduleMapCache = @{
}

<#
.SYNOPSIS
    Finds and validates a redirect for a dependency version.
    
.PARAMETER DependencyName
    The name of the dependency module.
    
.PARAMETER DependencyVersion
    The version of the dependency (can be exact version, range, or empty).
    Handles open-ended ranges like "[1.0, )", null/empty versions, exact versions, and exact ranges.
    
.PARAMETER RedirectMap
    The redirect map to search in. The map can contain:
    - "ModuleName@Version" -> "NewVersion" : Redirects specific version
    - "ModuleName" -> "Version" : Redirects all versions of the module
    - "ModuleName@Version" -> "*" : Retains version but normalizes module name casing
    - "ModuleName" -> "*" : Retains version but normalizes module name casing
    
.PARAMETER Indent
    Indentation string for verbose messages.
    
.OUTPUTS
    Returns a hashtable with:
    - ResolvedVersion: The version after applying redirects
    - ResolvedName: The dependency name (may have corrected casing from redirect map)
    - IsRedirected: Boolean indicating if a redirect was applied
#>
function Find-DependencyRedirect {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DependencyName,
        
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DependencyVersion,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$RedirectMap,
        
        [Parameter(Mandatory = $false)]
        [string]$Indent = ""
    )
    
    # Check if version is empty/null - this requires conservative resolution
    if ([string]::IsNullOrWhiteSpace($DependencyVersion)) {
        # Try to resolve from redirect map (name-only)
        if ($RedirectMap.ContainsKey($DependencyName)) {
            $depVersion = $RedirectMap[$DependencyName]
            Write-Verbose "${Indent}Resolved unversioned dependency: $DependencyName -> $depVersion (from redirect map)"
            
            # Extract corrected casing from redirect map key
            $resolvedName = $DependencyName
            foreach ($entry in $RedirectMap.GetEnumerator()) {
                if ($entry.Key -eq $DependencyName) {
                    $resolvedName = $entry.Key
                    break
                }
            }
            
            return @{
                ResolvedVersion = $depVersion
                ResolvedName = $resolvedName
                IsRedirected = $true
            }
        }
        else {
            throw "${Indent}Cannot conservatively resolve version for dependency '$DependencyName'. Please add a redirect mapping for this module."
        }
    }
    
    # Check if this is an exact version specification
    $isExactVersion = $true
    $normalizedDepVersion = $DependencyVersion
    
    # Check for version range:
    # like "[1.0, 1.0]", "[1.0, )", "(, 2.0]", etc.
    if ($DependencyVersion -match '^(\[|\()([^,]*),\s*([^\]\)]*)(\]|\))$') {
        # Extract both versions from the range
        $openBracket = $matches[1]
        $minVer = $matches[2]
        $maxVer = $matches[3]
        $closeBracket = $matches[4]
        
        if ($minVer -and $maxVer -and ($minVer -eq $maxVer) -and ($openBracket -eq '[') -and ($closeBracket -eq ']')) {
            # Exact version like "[1.0, 1.0]"
            $normalizedDepVersion = $minVer
        }
        elseif ($maxVer -and (-not $minVer)) {
            # Open-ended range like "(, 2.0]" - not exact
            $isExactVersion = $false
            $normalizedDepVersion = $maxVer
        }
        elseif ($minVer -and (-not $maxVer)) {
            # Open-ended range like "[1.0, )" - not exact
            $isExactVersion = $false
            $normalizedDepVersion = $minVer
        }
        else {
            # Any other range like "[1.0, 2.0]" - not exact
            $isExactVersion = $false
            $normalizedDepVersion = $minVer
        }
    }
    
    # Apply redirect if exists - check name@version first, then name-only fallback
    # Single iteration to find both potential matches, prioritize version-specific
    $depKeyPattern = "${DependencyName}@${normalizedDepVersion}"
    $versionSpecificEntry = $null
    $nameOnlyEntry = $null
    
    foreach ($entry in $RedirectMap.GetEnumerator()) {
        if ($entry.Key -eq $depKeyPattern) {
            $versionSpecificEntry = $entry
            break  # Version-specific is highest priority, can stop
        }
        elseif ($null -eq $nameOnlyEntry -and $entry.Key -eq $DependencyName) {
            $nameOnlyEntry = $entry
            # Continue searching for version-specific
        }
    }
    
    $matchedEntry = if ($versionSpecificEntry) { $versionSpecificEntry } else { $nameOnlyEntry }
    $isNameOnlyMatch = $null -eq $versionSpecificEntry -and $null -ne $nameOnlyEntry
    
    if ($matchedEntry) {
        $resolvedVersion = $matchedEntry.Value
        
        # Handle special "*" value - retain version but normalize dependency name
        if ($resolvedVersion -eq "*") {
            $resolvedVersion = $normalizedDepVersion
            
            if ($isNameOnlyMatch) {
                $resolvedName = $matchedEntry.Key
            }
            else {
                $resolvedName = $matchedEntry.Key -replace '@.*$', ''
            }
            
            Write-Verbose "${Indent}Normalizing dependency name: $DependencyName -> $resolvedName (version $normalizedDepVersion retained)"
            
            return @{
                ResolvedVersion = $resolvedVersion
                ResolvedName = $resolvedName
                IsRedirected = $true
            }
        }
        
        # If this is an exact version specification, verify the redirect points to the same version
        if ($isExactVersion -and $resolvedVersion -ne $normalizedDepVersion) {
            throw "${Indent}Cannot redirect exact version dependency '$DependencyName' from version $normalizedDepVersion to $resolvedVersion. Exact version specifications must redirect to the same version or have no redirect."
        }
        
        if ($isNameOnlyMatch) {
            $resolvedName = $matchedEntry.Key
            Write-Verbose "${Indent}Redirecting dependency: $DependencyName $DependencyVersion -> $resolvedVersion (from name-only redirect)"
        }
        else {
            $resolvedName = $matchedEntry.Key -replace '@.*$', ''
            Write-Verbose "${Indent}Redirecting dependency: $DependencyName $DependencyVersion -> $resolvedVersion (from redirect map)"
        }
        
        return @{
            ResolvedVersion = $resolvedVersion
            ResolvedName = $resolvedName
            IsRedirected = $true
        }
    }
    else {
        return @{
            ResolvedVersion = $normalizedDepVersion
            ResolvedName = $DependencyName
            IsRedirected = $false
        }
    }
}

<#
.SYNOPSIS
    Merges redirect maps with proper precedence.
    
.PARAMETER OuterMap
    The outer/parameter map that takes precedence in case of key collision.
    
.PARAMETER Name
    The name of the module to load module-specific map for.
    
.PARAMETER Version
    The version of the module to load module-specific map for.
#>
function Get-MergedRedirectMap {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$OuterMap,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Version
    )
    
    $redirectMap = $OuterMap
    
    # Handle empty or null version - only try name-only pattern
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $versionPatterns = @()
    }
    else {
        # Parse version - handle version ranges like "[1.3.9, 1.3.9]", "[1.3.9, )", etc.
        $baseVersion = $Version
        if ($Version -match '[\[\(]([0-9][0-9a-zA-Z.\-]*)') {
            # Extract the first version number from a version range
            $baseVersion = $matches[1]
        }
        
        # Extract major and minor using string splitting (supports prerelease versions like "1.0.0-preview")
        $versionParts = $baseVersion -split '[.\-]'
        $major = $versionParts[0]
        $minor = if ($versionParts.Count -gt 1) { $versionParts[1] } else { "0" }
        $versionPatterns = @(
            $baseVersion,  # Full version (e.g., 1.4.0.15939652 or 1.0.0-preview)
            "$major.$minor",  # Major.Minor (e.g., 1.4)
            "$major"  # Major only (e.g., 1)
        )
    }
    
    # Try each version pattern
    $moduleMap = $null
    foreach ($versionPattern in $versionPatterns) {
        $cacheKey = "$Name@$versionPattern"
        
        # Check cache for this pattern
        if ($script:moduleMapCache.ContainsKey($cacheKey)) {
            Write-Verbose "Using cached redirect map for: $cacheKey"
            $moduleMap = $script:moduleMapCache[$cacheKey]
            break
        }
        
        # Check if file exists for this pattern
        $testPath = Join-Path $PSScriptRoot "maps" "$Name@$versionPattern.json"
        if (Test-Path $testPath) {
            Write-Verbose "Loading module-specific redirect map from: $testPath"
            $moduleMap = Get-Content $testPath -Raw | ConvertFrom-Json -AsHashtable
            
            # Cache the loaded map under this pattern
            $script:moduleMapCache[$cacheKey] = $moduleMap
            break
        }
    }
    
    # Merge maps if module-specific map exists
    if ($moduleMap) {
        # Merge maps with outer map taking precedence
        $mergedMap = @{}
        foreach ($key in $moduleMap.Keys) {
            $mergedMap[$key] = $moduleMap[$key]
        }
        foreach ($key in $redirectMap.Keys) {
            $mergedMap[$key] = $redirectMap[$key]  # Outer map wins
        }
        $redirectMap = $mergedMap
    }
    
    return $redirectMap
}

<#
.SYNOPSIS
    Builds a complete dependency graph for a module from a remote repository.
    
.DESCRIPTION
    This function builds a dependency graph by recursively querying the repository
    for module metadata. Unlike Build-DependencyGraph (for installed modules),
    this uses Find-PSResource to query remote repositories.
    
.PARAMETER ModuleName
    The name of the module.
    
.PARAMETER ModuleVersion
    The version of the module.
    
.PARAMETER Graph
    The hashtable to build the graph into.
    
.PARAMETER RedirectMap
    The redirect map for version resolution.
    
.PARAMETER Repository
    The repository to search in.
    
.PARAMETER Credential
    Credentials for repository access.
    
.PARAMETER Depth
    Current recursion depth for indentation.
#>
function Build-RemoteDependencyGraph {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$ModuleVersion,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$RedirectMap,
        
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Prerelease,
        
        [Parameter(Mandatory = $false)]
        [int]$Depth = 0
    )
    
    $indent = "  " * $Depth
    $moduleKey = "${ModuleName}@${ModuleVersion}"
    
    # Skip if already processed
    if ($Graph.ContainsKey($moduleKey)) {
        Write-Verbose "${indent}Already in graph: $moduleKey"
        return
    }
    
    # Find the module in the repository
    $findParams = @{
        Name = $ModuleName
        Version = $ModuleVersion
    }
    if ($Repository) {
        $findParams['Repository'] = $Repository
    }
    if ($Credential) {
        $findParams['Credential'] = $Credential
    }
    if ($Prerelease) {
        $findParams['Prerelease'] = $Prerelease
    }
    
    Write-Verbose "Looking for dependencies: $ModuleName version $ModuleVersion"
    $moduleInfo = Find-PSResource @findParams -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if (-not $moduleInfo) {
        throw "Module not found: $ModuleName version $ModuleVersion"
    }
    
    Write-Verbose "${indent}Building graph for: $ModuleName version $ModuleVersion"
    
    # Initialize graph node
    $graphNode = @{
        Name = $ModuleName
        Version = $ModuleVersion
        Dependencies = [System.Collections.ArrayList]@()
        Repository = $moduleInfo.Repository
    }
    $Graph[$moduleKey] = $graphNode
    
    # Get dependencies
    $deps = $moduleInfo.Dependencies
    if (-not $deps -or $deps.Count -eq 0) {
        Write-Verbose "${indent}No dependencies for $ModuleName"
        return
    }
    
    Write-Verbose "${indent}Found $($deps.Count) dependency(ies)"
    
    foreach ($dep in $deps) {
        $depName = $dep.Name
        $depVersion = $dep.VersionRange
        
        # Apply redirect to resolve version
        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
            -RedirectMap $RedirectMap -Indent $indent
        
        $resolvedDepVersion = $redirectResult.ResolvedVersion
        $resolvedDepName = $redirectResult.ResolvedName
        
        $depKey = "${resolvedDepName}@${resolvedDepVersion}"
        Write-Verbose "${indent}  Dependency: $depKey"
        
        # Add to this node's dependencies
        [void]$graphNode.Dependencies.Add($depKey)
        
        # Merge redirect map for this dependency
        $depRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $resolvedDepName -Version $resolvedDepVersion
        
        # Recursively build graph for this dependency
        Build-RemoteDependencyGraph -ModuleName $resolvedDepName -ModuleVersion $resolvedDepVersion `
            -Graph $Graph -RedirectMap $depRedirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease -Depth ($Depth + 1)
    }
}

<#
.SYNOPSIS
    Compares two semantic version strings, including prerelease labels.
    
.DESCRIPTION
    Compares version strings that may include prerelease suffixes (e.g., "1.0.0-dev", "2.0.0-beta.1").
    Returns -1 if Version1 < Version2, 0 if equal, 1 if Version1 > Version2.
    Prerelease versions are considered lower than their release counterparts (1.0.0-alpha < 1.0.0).
    
.PARAMETER Version1
    The first version string to compare.
    
.PARAMETER Version2
    The second version string to compare.
#>
function Compare-SemVer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version1,
        
        [Parameter(Mandatory = $true)]
        [string]$Version2
    )
    
    # Split version and prerelease parts
    $v1Parts = $Version1 -split '-', 2
    $v2Parts = $Version2 -split '-', 2
    
    $v1Base = $v1Parts[0]
    $v2Base = $v2Parts[0]
    $v1Prerelease = if ($v1Parts.Count -gt 1) { $v1Parts[1] } else { $null }
    $v2Prerelease = if ($v2Parts.Count -gt 1) { $v2Parts[1] } else { $null }
    
    # Compare base versions
    try {
        $v1Ver = [System.Version]$v1Base
        $v2Ver = [System.Version]$v2Base
        $baseCompare = $v1Ver.CompareTo($v2Ver)
    }
    catch {
        # Fallback to string comparison if version parsing fails
        $baseCompare = [string]::Compare($v1Base, $v2Base, [StringComparison]::OrdinalIgnoreCase)
    }
    
    if ($baseCompare -ne 0) {
        return $baseCompare
    }
    
    # Base versions are equal, compare prerelease
    # No prerelease > any prerelease (1.0.0 > 1.0.0-alpha)
    if ($null -eq $v1Prerelease -and $null -eq $v2Prerelease) {
        return 0
    }
    if ($null -eq $v1Prerelease) {
        return 1  # v1 is release, v2 is prerelease
    }
    if ($null -eq $v2Prerelease) {
        return -1  # v1 is prerelease, v2 is release
    }
    
    # Both have prerelease, compare lexicographically
    # This handles cases like alpha < beta < dev < rc
    return [string]::Compare($v1Prerelease, $v2Prerelease, [StringComparison]::OrdinalIgnoreCase)
}

<#
.SYNOPSIS
    Resolves diamond dependencies in a dependency graph by selecting the highest version.
    
.DESCRIPTION
    When multiple versions of the same module exist in the graph (diamond dependency),
    this function selects the highest version and updates all references.
    
.PARAMETER Graph
    The dependency graph hashtable to resolve.
#>
function Resolve-DiamondDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph
    )
    
    # Group nodes by module name (without version)
    $moduleVersions = @{}
    foreach ($nodeKey in $Graph.Keys) {
        $node = $Graph[$nodeKey]
        $moduleName = $node.Name
        if (-not $moduleVersions.ContainsKey($moduleName)) {
            $moduleVersions[$moduleName] = @()
        }
        $moduleVersions[$moduleName] += @{
            Key = $nodeKey
            VersionString = $node.Version
            Node = $node
        }
    }
    
    # Find and resolve conflicts - select highest version
    foreach ($moduleName in $moduleVersions.Keys) {
        $versions = $moduleVersions[$moduleName]
        if ($versions.Count -gt 1) {
            # Sort using Compare-SemVer for proper semver ordering (descending)
            $sorted = $versions | Sort-Object -Property @{
                Expression = {
                    # Create a sortable key: base version padded + prerelease indicator + prerelease label
                    $ver = $_.VersionString
                    $parts = $ver -split '-', 2
                    $base = $parts[0]
                    $prerelease = if ($parts.Count -gt 1) { $parts[1] } else { $null }
                    
                    # Pad version parts for proper numeric sorting
                    $verParts = $base -split '\.'
                    $paddedBase = ($verParts | ForEach-Object { $_.PadLeft(10, '0') }) -join '.'
                    
                    # Release versions sort after prereleases (z > any prerelease label)
                    $prereleaseKey = if ($null -eq $prerelease) { 'zzzzzzzzzz' } else { $prerelease }
                    
                    "$paddedBase|$prereleaseKey"
                }
                Descending = $true
            }
            
            $highest = $sorted[0]
            $conflicts = $sorted | Select-Object -Skip 1
            
            Write-Warning "Diamond dependency detected for '$moduleName': versions $($versions.VersionString -join ', '). Using highest: $($highest.VersionString)"
            
            foreach ($conflict in $conflicts) {
                $oldKey = $conflict.Key
                $newKey = $highest.Key
                
                Write-Verbose "  Redirecting $oldKey -> $newKey"
                
                # Update all references from old version to new version
                foreach ($nodeKey in $Graph.Keys) {
                    $node = $Graph[$nodeKey]
                    for ($i = 0; $i -lt $node.Dependencies.Count; $i++) {
                        if ($node.Dependencies[$i] -eq $oldKey) {
                            $node.Dependencies[$i] = $newKey
                        }
                    }
                }
                
                # Remove the old version node from the graph
                $Graph.Remove($oldKey)
            }
        }
    }
}

<#
.SYNOPSIS
    Computes topological order of a dependency graph.
    
.DESCRIPTION
    Returns an array of module keys in dependency order (dependencies first).
    Detects and warns about circular dependencies.
    
.PARAMETER Graph
    The dependency graph hashtable.
#>
function Get-TopologicalOrder {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph
    )
    
    $visited = @{}
    $visiting = @{}  # For cycle detection
    $order = [System.Collections.ArrayList]@()
    
    function Visit {
        param([string]$NodeKey)
        
        if ($visited.ContainsKey($NodeKey)) {
            return
        }
        
        if ($visiting.ContainsKey($NodeKey)) {
            Write-Warning "Circular dependency detected involving: $NodeKey"
            return
        }
        
        $visiting[$NodeKey] = $true
        
        if ($Graph.ContainsKey($NodeKey)) {
            $node = $Graph[$NodeKey]
            foreach ($depKey in $node.Dependencies) {
                Visit -NodeKey $depKey
            }
        }
        
        $visiting.Remove($NodeKey)
        $visited[$NodeKey] = $true
        [void]$order.Add($NodeKey)
    }
    
    # Visit all nodes
    foreach ($nodeKey in $Graph.Keys) {
        Visit -NodeKey $nodeKey
    }
    
    return $order.ToArray()
}

<#
.SYNOPSIS
    Builds a complete dependency graph for an installed module.
    
.DESCRIPTION
    This function builds a dependency graph by querying installed modules
    using Get-PSResource. Used by Import-ModulePinned to load modules
    with correct dependency versions.
    
.PARAMETER ModuleName
    The name of the module.
    
.PARAMETER ModuleVersion
    The version of the module.
    
.PARAMETER Graph
    The hashtable to build the graph into.
    
.PARAMETER RedirectMap
    The redirect map for version resolution.
    
.PARAMETER Depth
    Current recursion depth for indentation.
#>
function Build-InstalledDependencyGraph {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$ModuleVersion,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$RedirectMap,
        
        [Parameter(Mandatory = $false)]
        [int]$Depth = 0
    )
    
    $indent = "  " * $Depth
    $moduleKey = "${ModuleName}@${ModuleVersion}"
    
    # Skip if already processed
    if ($Graph.ContainsKey($moduleKey)) {
        Write-Verbose "${indent}Already in graph: $moduleKey"
        return
    }
    
    # Find the installed module
    $installedModule = Get-PSResource -Name $ModuleName -Version $ModuleVersion -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if (-not $installedModule) {
        throw "Module not found: $ModuleName version $ModuleVersion. Please install using Install-PSResourcePinned first."
    }
    
    $actualVersion = $installedModule.Version.ToString()
    Write-Verbose "${indent}Building graph for: $ModuleName version $actualVersion"
    
    # PSResource InstalledLocation is the base modules folder, need to add ModuleName/Version subpath
    $moduleVersionPath = Join-Path $installedModule.InstalledLocation $ModuleName $actualVersion
    
    # Initialize graph node
    $graphNode = @{
        Name = $ModuleName
        Version = $actualVersion
        Dependencies = [System.Collections.ArrayList]@()
        InstalledLocation = $moduleVersionPath
    }
    $Graph[$moduleKey] = $graphNode
    
    # Get dependencies from Get-PSResource
    $deps = $installedModule.Dependencies
    if (-not $deps -or $deps.Count -eq 0) {
        Write-Verbose "${indent}No dependencies for $ModuleName"
        return
    }
    
    Write-Verbose "${indent}Found $($deps.Count) dependency(ies)"
    
    foreach ($dep in $deps) {
        $depName = $dep.Name
        $depVersion = $dep.VersionRange
        
        # Apply redirect to resolve version
        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
            -RedirectMap $RedirectMap -Indent $indent
        
        $resolvedDepVersion = $redirectResult.ResolvedVersion
        $resolvedDepName = $redirectResult.ResolvedName
        
        $depKey = "${resolvedDepName}@${resolvedDepVersion}"
        Write-Verbose "${indent}  Dependency: $depKey"
        
        # Add to this node's dependencies
        [void]$graphNode.Dependencies.Add($depKey)
        
        # Merge redirect map for this dependency
        $depRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $resolvedDepName -Version $resolvedDepVersion
        
        # Recursively build graph for this dependency
        Build-InstalledDependencyGraph -ModuleName $resolvedDepName -ModuleVersion $resolvedDepVersion `
            -Graph $Graph -RedirectMap $depRedirectMap -Depth ($Depth + 1)
    }
}

function Install-PSResourcePinned {
    <#
    .SYNOPSIS
        Installs a PowerShell module with conservative dependency resolution and specific version redirects.
    
    .DESCRIPTION
        PowerCLI does not follow semver conventions and 13.4 breaks backward-compatibility in some of the dependencies.
        This function installs a module via PSResourceGet with exact version matching for dependencies,
        using a redirect map to handle known issues.
        
    .PARAMETER Name
        The name of the module to install.
        
    .PARAMETER RequiredVersion
        The version of the module to install.
        
    .PARAMETER RedirectMapPath
        Path to JSON file containing version redirects. If not specified, uses default map.
        
    .PARAMETER Scope
        Installation scope: CurrentUser or AllUsers. Default is CurrentUser.
        
    .PARAMETER Repository
        The repository to search for and install the module from. If not specified, searches all registered repositories.
        
    .PARAMETER Credential
        Credentials to use when accessing the repository.
        
    .EXAMPLE
        Install-PSResourcePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]$Scope = 'CurrentUser',
        
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Prerelease
    )
    
    # Load redirect map from file or use default
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Using default redirect map"
        $redirectMap = $script:defaultRedirectMap
    }
    
    # Merge with module-specific redirect map
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    # Build complete dependency graph
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-RemoteDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    
    # Resolve diamond dependencies
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    # Compute topological order (dependencies first)
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
    Write-Verbose "Install order ($($topologicalOrder.Count) modules):"
    for ($i = 0; $i -lt $topologicalOrder.Count; $i++) {
        Write-Verbose "  $($i + 1). $($topologicalOrder[$i])"
    }
    
    # Install modules in topological order
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        $modName = $node.Name
        $modVersion = $node.Version
        
        # Check if already installed with exact version (including prerelease label)
        $installed = Get-PSResource -Name $modName -ErrorAction SilentlyContinue | 
            Where-Object {
                if (-not $_) { return $false }
                $installedVersion = $_.Version.ToString()
                if ($_.Prerelease) {
                    $installedVersion = "$installedVersion-$($_.Prerelease)"
                }
                $installedVersion -eq $modVersion
            }
        
        if (-not $installed) {
            Write-Verbose "Installing: $modName version $modVersion"
            $installParams = @{
                Name = $modName
                Version = $modVersion
                Scope = $Scope
                Prerelease = $Prerelease
                TrustRepository = $true
                SkipDependencyCheck = $true
            }
            if ($Repository) {
                $installParams['Repository'] = $Repository
            }
            if ($Credential) {
                $installParams['Credential'] = $Credential
            }
            
            Install-PSResource @installParams
        }
        else {
            Write-Verbose "Already installed: $modName version $modVersion"
        }
    }
    
    $mainModuleKey = "${Name}@${RequiredVersion}"
    $mainNode = $dependencyGraph[$mainModuleKey]
    Write-Host "Successfully installed $Name version $($mainNode.Version)"
}

function Save-PSResourcePinned {
    <#
    .SYNOPSIS
        Downloads a PowerShell module as NuGet packages with conservative dependency resolution.
    
    .DESCRIPTION
        This function downloads a module and all its dependencies as NuGet packages (.nupkg files)
        to a specified destination path, using the same conservative dependency resolution logic
        as Install-PSResourcePinned.
        
    .PARAMETER Name
        The name of the module to download.
        
    .PARAMETER RequiredVersion
        The version of the module to download.
        
    .PARAMETER Path
        The destination path where NuGet packages will be saved.
        
    .PARAMETER RedirectMapPath
        Path to JSON file containing version redirects. If not specified, uses default map.
        
    .PARAMETER Repository
        The repository to search for and download the module from. If not specified, searches all registered repositories.
        
    .PARAMETER Credential
        Credentials to use when accessing the repository.
        
    .PARAMETER AsNupkg
        Save the module as a .nupkg file. Default is $true.
        
    .EXAMPLE
        Save-PSResourcePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0" -Path "./packages"
        
    .EXAMPLE
        Save-PSResourcePinned -Name "Microsoft.AVS.Management" -RequiredVersion "1.0.0" -Path "C:\Packages" -Repository PSGallery
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsNupkg = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$Prerelease
    )
    
    # Validate and create destination path if needed
    if (-not (Test-Path $Path)) {
        Write-Verbose "Creating destination directory: $Path"
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $resolvedPath = Resolve-Path $Path
    Write-Verbose "Saving packages to: $resolvedPath"
    
    # Load redirect map from file or use default
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Using default redirect map"
        $redirectMap = $script:defaultRedirectMap
    }
    
    # Merge with module-specific redirect map
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    # Build complete dependency graph
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-RemoteDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    
    # Resolve diamond dependencies
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    # Compute topological order (dependencies first)
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
    Write-Verbose "Save order ($($topologicalOrder.Count) modules):"
    for ($i = 0; $i -lt $topologicalOrder.Count; $i++) {
        Write-Verbose "  $($i + 1). $($topologicalOrder[$i])"
    }
    
    # Save modules in topological order
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        $modName = $node.Name
        $modVersion = $node.Version
        
        # Check if already saved
        $expectedFileName = "$modName.$modVersion.nupkg"
        $expectedPath = Join-Path $resolvedPath.Path $expectedFileName
        
        if (-not (Test-Path $expectedPath)) {
            Write-Verbose "Saving: $modName version $modVersion"
            $saveParams = @{
                Name = $modName
                Version = $modVersion
                Path = $resolvedPath.Path
                Prerelease = $Prerelease
                TrustRepository = $true
                SkipDependencyCheck = $true
            }
            if ($AsNupkg) {
                $saveParams['AsNupkg'] = $true
            }
            if ($Repository) {
                $saveParams['Repository'] = $Repository
            }
            if ($Credential) {
                $saveParams['Credential'] = $Credential
            }
            
            Save-PSResource @saveParams
        }
        else {
            Write-Verbose "Already saved: $modName version $modVersion"
        }
    }
    
    $mainModuleKey = "${Name}@${RequiredVersion}"
    $mainNode = $dependencyGraph[$mainModuleKey]
    Write-Host "Successfully saved $Name version $($mainNode.Version) and dependencies to $resolvedPath"
}

function Find-PSResourceDependencies {
    <#
    .SYNOPSIS
        Finds and resolves dependencies from a PowerShell module manifest with conservative version resolution.
    
    .DESCRIPTION
        This function reads a .psd1 module manifest file and resolves all RequiredModules
        and their transitive dependencies using graph-based dependency resolution.
        Returns an array of resolved dependencies with their names and versions.
        
    .PARAMETER ManifestPath
        The path to the .psd1 module manifest file.
        
    .PARAMETER RedirectMapPath
        Path to JSON file containing version redirects. If not specified, looks for a redirect map
        in the maps directory based on the manifest's module name and version.
        
    .PARAMETER Repository
        The repository to search for and resolve module dependencies from.
        If not specified, searches all registered repositories.
        
    .PARAMETER Credential
        Credentials to use when accessing the repository.
        
    .EXAMPLE
        Find-PSResourceDependencies -ManifestPath "./MyModule/MyModule.psd1"
        
    .EXAMPLE
        Find-PSResourceDependencies -ManifestPath "./MyModule.psd1" -RedirectMapPath "./redirects.json"
        
    .OUTPUTS
        Returns an array of PSCustomObject with Name, Version, and OriginalVersion properties for each resolved dependency.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Prerelease
    )
    
    # Validate manifest path
    if (-not (Test-Path $ManifestPath)) {
        throw "Manifest file not found: $ManifestPath"
    }
    
    $resolvedPath = Resolve-Path $ManifestPath
    if (-not $resolvedPath.Path.EndsWith('.psd1')) {
        throw "File must be a PowerShell module manifest (.psd1): $ManifestPath"
    }
    
    Write-Verbose "Reading manifest from: $resolvedPath"
    
    # Parse the manifest
    $manifest = Import-PowerShellDataFile -Path $resolvedPath
    
    # Check if RequiredModules exists and has content
    $hasRequiredModules = $manifest.ContainsKey('RequiredModules') -and $manifest.RequiredModules -and $manifest.RequiredModules.Count -gt 0
    if (-not $hasRequiredModules) {
        Write-Verbose "No RequiredModules found in manifest"
        return @()
    }
    
    # Extract module name and version from manifest for redirect map lookup
    $manifestModuleName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPath.Path)
    $manifestModuleVersion = if ($manifest.ModuleVersion) { $manifest.ModuleVersion.ToString() } else { "" }
    
    # Load redirect map from file or use default
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Looking for redirect map based on manifest: $manifestModuleName version $manifestModuleVersion"
        # Merge default map with module-specific map based on manifest name and version
        $redirectMap = Get-MergedRedirectMap -OuterMap $script:defaultRedirectMap -Name $manifestModuleName -Version $manifestModuleVersion
    }
    
    Write-Verbose "Found $($manifest.RequiredModules.Count) required module(s) in manifest"
    
    # Build complete dependency graph for all required modules
    $dependencyGraph = @{}
    
    foreach ($requiredModule in $manifest.RequiredModules) {
        $moduleName = $null
        $moduleVersion = $null
        
        # RequiredModules can be a string (module name only) or a hashtable with ModuleName and ModuleVersion/RequiredVersion
        if ($requiredModule -is [string]) {
            $moduleName = $requiredModule
        }
        elseif ($requiredModule -is [hashtable]) {
            $moduleName = $requiredModule.ModuleName
            # Check for RequiredVersion first (exact version), then ModuleVersion (minimum version)
            if ($requiredModule.RequiredVersion) {
                $moduleVersion = $requiredModule.RequiredVersion.ToString()
            }
            elseif ($requiredModule.ModuleVersion) {
                # ModuleVersion in manifest means minimum version, treat as open-ended range
                $moduleVersion = "[$($requiredModule.ModuleVersion), )"
            }
        }
        else {
            Write-Warning "Skipping unrecognized RequiredModule format: $requiredModule"
            continue
        }
        
        if (-not $moduleName) {
            Write-Warning "Skipping RequiredModule with no module name"
            continue
        }
        
        # Apply redirect to resolve version
        $mergedRedirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $moduleName -Version ($moduleVersion ?? "")
        $redirectResult = Find-DependencyRedirect -DependencyName $moduleName -DependencyVersion $moduleVersion `
            -RedirectMap $mergedRedirectMap -Indent ""
        
        # Build dependency graph for this required module
        Build-RemoteDependencyGraph -ModuleName $redirectResult.ResolvedName -ModuleVersion $redirectResult.ResolvedVersion `
            -Graph $dependencyGraph -RedirectMap $mergedRedirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    }
    
    # Resolve diamond dependencies
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    # Compute topological order
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
    # Build result array in topological order
    $resolvedDependencies = [System.Collections.ArrayList]@()
    
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        
        [void]$resolvedDependencies.Add([PSCustomObject]@{
            Name = $node.Name
            Version = $node.Version
            Repository = $node.Repository
            IsRedirected = $false  # Graph already has redirected versions applied
        })
    }
    
    Write-Verbose "Resolved $($resolvedDependencies.Count) module(s) (including transitive dependencies)"
    
    return $resolvedDependencies.ToArray()
}

function Install-PSResourceDependencies {
    <#
    .SYNOPSIS
        Installs dependencies from a PowerShell module manifest with conservative version resolution.
    
    .DESCRIPTION
        This function reads a .psd1 module manifest file and installs all RequiredModules
        using the same conservative dependency resolution logic as Install-PSResourcePinned.
        
    .PARAMETER ManifestPath
        The path to the .psd1 module manifest file.
        
    .PARAMETER RedirectMapPath
        Path to JSON file containing version redirects. If not specified, looks for a redirect map
        in the maps directory based on the manifest's module name and version.
        
    .PARAMETER Scope
        Installation scope: CurrentUser or AllUsers. Default is CurrentUser.
        
    .PARAMETER Repository
        The repository to search for and install modules from. If not specified, searches all registered repositories.
        
    .PARAMETER Credential
        Credentials to use when accessing the repository.
        
    .EXAMPLE
        Install-PSResourceDependencies -ManifestPath "./MyModule/MyModule.psd1"
        
    .EXAMPLE
        Install-PSResourceDependencies -ManifestPath "./MyModule.psd1" -Scope AllUsers -Repository PSGallery
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]$Scope = 'CurrentUser',
        
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    # Find and resolve all dependencies (already in topological order)
    $findParams = @{
        ManifestPath = $ManifestPath
    }
    if ($RedirectMapPath) {
        $findParams['RedirectMapPath'] = $RedirectMapPath
    }
    if ($Repository) {
        $findParams['Repository'] = $Repository
    }
    if ($Credential) {
        $findParams['Credential'] = $Credential
    }
    
    $resolvedDependencies = Find-PSResourceDependencies @findParams
    
    if (-not $resolvedDependencies -or $resolvedDependencies.Count -eq 0) {
        Write-Verbose "No dependencies to install"
        return
    }
    
    Write-Verbose "Installing $($resolvedDependencies.Count) resolved dependency(ies)"
    
    # Dependencies are already in topological order from Find-PSResourceDependencies
    foreach ($dependency in $resolvedDependencies) {
        # Check if already installed with exact version
        $installed = Get-PSResource -Name $dependency.Name -ErrorAction SilentlyContinue | 
            Where-Object { $_.Version.ToString() -eq $dependency.Version }
        
        if (-not $installed) {
            Write-Host "Installing dependency: $($dependency.Name) version $($dependency.Version)"
            
            $installParams = @{
                Name = $dependency.Name
                Version = $dependency.Version
                Scope = $Scope
                TrustRepository = $true
                SkipDependencyCheck = $true
            }
            if ($Repository) {
                $installParams['Repository'] = $Repository
            }
            if ($Credential) {
                $installParams['Credential'] = $Credential
            }
            
            Install-PSResource @installParams
        }
        else {
            Write-Verbose "Already installed: $($dependency.Name) version $($dependency.Version)"
        }
    }
    
    Write-Host "Successfully installed all dependencies from manifest"
}

function Import-ModulePinned {
    <#
    .SYNOPSIS
        Imports a PowerShell module with explicit, recursive dependency loading at required versions.
    
    .DESCRIPTION
        This function imports a module by first building the complete transitive dependency graph,
        computing topological order, and pre-loading ALL dependencies with exact versions before
        importing the main module. This prevents PowerShell's manifest processing from loading
        wrong versions due to minimum version semantics.
        
    .PARAMETER Name
        The name of the module to import.
        
    .PARAMETER RequiredVersion
        The exact version of the module to import.
        
    .PARAMETER RedirectMapPath
        Path to JSON file containing version redirects. If not specified, uses default map.
        
    .PARAMETER Force
        Force reimport of the module even if already loaded.
        
    .PARAMETER Prefix
        Prefix to add to the nouns of imported commands.
        
    .PARAMETER PassThru
        Returns the module info object after import.
        
    .EXAMPLE
        Import-ModulePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0"
        
    .EXAMPLE
        Import-ModulePinned -Name "Microsoft.AVS.Management" -RequiredVersion "1.0.0" -Force -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$RequiredVersion,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [string]$Prefix,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    # Load redirect map from file or use default
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Using default redirect map"
        $redirectMap = $script:defaultRedirectMap
    }
    
    # Merge with module-specific redirect map
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    # Build complete dependency graph using shared function
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-InstalledDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap
    
    # Resolve diamond dependencies using shared function
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    Write-Verbose "Dependency graph contains $($dependencyGraph.Count) modules:"
    
    foreach ($nodeKey in $dependencyGraph.Keys | Sort-Object) {
        $node = $dependencyGraph[$nodeKey]
        Write-Verbose "  $nodeKey"
        Write-Verbose "    Location: $($node.InstalledLocation)"
        if ($node.Dependencies.Count -gt 0) {
            Write-Verbose "    Dependencies:"
            foreach ($dep in $node.Dependencies) {
                Write-Verbose "      -> $dep"
            }
        }
        else {
            Write-Verbose "    Dependencies: (none)"
        }
    }
    
    # Compute topological order using shared function
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
    Write-Verbose "Import order ($($topologicalOrder.Count) modules):"
    for ($i = 0; $i -lt $topologicalOrder.Count; $i++) {
        Write-Verbose "  $($i + 1). $($topologicalOrder[$i])"
    }
    Write-Verbose "Pre-loading all modules in topological order"
    
    $importedModules = @{}
    
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        $modName = $node.Name
        $modVersion = $node.Version
        
        # Check if already loaded with exact version
        $loadedModule = Get-Module -Name $modName | Where-Object { $_.Version.ToString() -eq $modVersion }
        
        if ($loadedModule -and -not $Force) {
            Write-Verbose "Already loaded: $modName version $modVersion"
            $importedModules[$moduleKey] = $loadedModule
            continue
        }
        
        # Import with exact version
        # Always use -Global to ensure modules persist after this function returns
        $importParams = @{
            Name = $modName
            RequiredVersion = $modVersion
            ErrorAction = 'Stop'
            DisableNameChecking = $true
            Global = $true
        }
        
        if ($Force) {
            $importParams['Force'] = $true
        }
        
        try {
            Write-Verbose "Importing: $modName version $modVersion"
            $imported = Import-Module @importParams -PassThru
            $importedModules[$moduleKey] = $imported
        }
        catch {
            throw "Failed to import $modName version $($modVersion): $_"
        }
    }
    
    Write-Verbose "Returning main module"
    
    # The main module should already be loaded from the topological import
    $mainModuleKey = "${Name}@${RequiredVersion}"
    $mainModule = $importedModules[$mainModuleKey]
    
    if (-not $mainModule) {
        # Shouldn't happen, but fallback just in case
        $mainModule = Get-Module -Name $Name | Where-Object { $_.Version.ToString() -eq $RequiredVersion }
    }
    
    Write-Verbose "Successfully imported $Name version $RequiredVersion (and $($importedModules.Count - 1) dependencies)"
    
    if ($PassThru) {
        return $mainModule
    }
}

function Find-PSResourcesPinned {
    <#
    .SYNOPSIS
        Finds a PowerShell module and all its dependencies with conservative version resolution.
    
    .DESCRIPTION
        This function searches for a module and resolves all its dependencies using
        graph-based dependency resolution. Returns an array of objects for the main
        module and all dependencies in topological order.
        
    .PARAMETER Name
        The name of the module to find.
        
    .PARAMETER RequiredVersion
        The version of the module to find.
        
    .PARAMETER RedirectMapPath
        Path to JSON file containing version redirects. If not specified, uses default map.
        
    .PARAMETER Repository
        The repository to search for the module from. If not specified, searches all registered repositories.
        
    .PARAMETER Credential
        Credentials to use when accessing the repository.
        
    .EXAMPLE
        Find-PSResourcesPinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0"
        
    .EXAMPLE
        Find-PSResourcesPinned -Name "Microsoft.AVS.Management" -RequiredVersion "1.0.0" -Repository PSGallery
        
    .OUTPUTS
        Returns an array of objects with Name, Version, Repository and Dependencies properties for each resolved module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Prerelease
    )
    
    # Load redirect map from file or use default
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Using default redirect map"
        $redirectMap = $script:defaultRedirectMap
    }
    
    # Merge with module-specific redirect map
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    # Build complete dependency graph
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-RemoteDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    
    # Resolve diamond dependencies
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    # Compute topological order
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
    # Build result array in topological order
    $resolvedModules = [System.Collections.ArrayList]@()
    
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        
        [void]$resolvedModules.Add([PSCustomObject]@{
            Name = $node.Name
            Version = $node.Version
            Repository = $node.Repository
            Dependencies = $node.Dependencies
        })
    }
    
    Write-Verbose "Found $($resolvedModules.Count) module(s) (including main module and all dependencies)"
    
    return $resolvedModules.ToArray()
}