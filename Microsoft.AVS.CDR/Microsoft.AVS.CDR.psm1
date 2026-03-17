$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

class DependencyGraphNode {
    [string]$Name
    [string]$Version
    [System.Collections.ArrayList]$Dependencies
    [bool]$NotFound
    [string]$Repository
    [string]$InstalledLocation

    DependencyGraphNode(
        [string]$Name,
        [string]$Version,
        [System.Collections.IList]$Dependencies,
        [bool]$NotFound,
        [string]$Repository,
        [string]$InstalledLocation
    ) {
        $this.Name = $Name
        $this.Version = $Version
        $this.Dependencies = [System.Collections.ArrayList]::new($Dependencies)
        $this.NotFound = $NotFound
        $this.Repository = $Repository
        $this.InstalledLocation = $InstalledLocation
    }
}

$script:defaultRedirectMap = @{
}

$script:moduleMapCache = @{
}

<#
.SYNOPSIS
    Finds and validates a redirect for a dependency version.
    
.PARAMETER RedirectMap
    Map entries: "Name@Version" -> "NewVersion", "Name" -> "Version",
    "Name@Version" -> "*" or "Name" -> "*" (retain version, normalize casing).
    
.OUTPUTS
    Hashtable with ResolvedVersion, ResolvedName, and IsRedirected.
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
    
    if ([string]::IsNullOrWhiteSpace($DependencyVersion)) {
        if ($RedirectMap.ContainsKey($DependencyName)) {
            $depVersion = $RedirectMap[$DependencyName]
            Write-Verbose "${Indent}Resolved unversioned dependency: $DependencyName -> $depVersion (from redirect map)"
            
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
    
    $isExactVersion = $true
    $normalizedDepVersion = $DependencyVersion
    
    # Version range like "[1.0, 1.0]", "[1.0, )", "(, 2.0]"
    if ($DependencyVersion -match '^(\[|\()([^,]*),\s*([^\]\)]*)(\]|\))$') {
        $openBracket = $matches[1]
        $minVer = $matches[2]
        $maxVer = $matches[3]
        $closeBracket = $matches[4]
        
        if ($minVer -and $maxVer -and ($minVer -eq $maxVer) -and ($openBracket -eq '[') -and ($closeBracket -eq ']')) {
            $normalizedDepVersion = $minVer  # exact: [1.0, 1.0]
        }
        elseif ($maxVer -and (-not $minVer)) {
            $isExactVersion = $false
            $normalizedDepVersion = $maxVer  # open-ended: (, 2.0]
        }
        elseif ($minVer -and (-not $maxVer)) {
            $isExactVersion = $false
            $normalizedDepVersion = $minVer  # open-ended: [1.0, )
        }
        else {
            $isExactVersion = $false
            $normalizedDepVersion = $minVer
        }
    }
    
    # Check name@version first, then name-only fallback
    $depKeyPattern = "${DependencyName}@${normalizedDepVersion}"
    $versionSpecificEntry = $null
    $nameOnlyEntry = $null
    
    foreach ($entry in $RedirectMap.GetEnumerator()) {
        if ($entry.Key -eq $depKeyPattern) {
            $versionSpecificEntry = $entry
            break
        }
        elseif ($null -eq $nameOnlyEntry -and $entry.Key -eq $DependencyName) {
            $nameOnlyEntry = $entry
        }
    }
    
    $matchedEntry = if ($versionSpecificEntry) { $versionSpecificEntry } else { $nameOnlyEntry }
    $isNameOnlyMatch = $null -eq $versionSpecificEntry -and $null -ne $nameOnlyEntry
    
    if ($matchedEntry) {
        $resolvedVersion = $matchedEntry.Value
        
        # "*" retains version but normalizes dependency name casing
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
    Merges redirect maps — OuterMap takes precedence. Loads module-specific map files from maps/ dir.
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
    
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $versionPatterns = @()
    }
    else {
        $baseVersion = $Version
        if ($Version -match '[\[\(]([0-9][0-9a-zA-Z.\-]*)') {
            $baseVersion = $matches[1]
        }
        
        $versionParts = $baseVersion -split '[.\-]'
        $major = $versionParts[0]
        $minor = if ($versionParts.Count -gt 1) { $versionParts[1] } else { "0" }
        $versionPatterns = @(
            $baseVersion,  # Full version (e.g., 1.4.0.15939652 or 1.0.0-preview)
            "$major.$minor",  # Major.Minor (e.g., 1.4)
            "$major"  # Major only (e.g., 1)
        )
    }
    
    $moduleMap = $null
    foreach ($versionPattern in $versionPatterns) {
        $cacheKey = "$Name@$versionPattern"
        
        if ($script:moduleMapCache.ContainsKey($cacheKey)) {
            Write-Verbose "Using cached redirect map for: $cacheKey"
            $moduleMap = $script:moduleMapCache[$cacheKey]
            break
        }
        
        $testPath = Join-Path $PSScriptRoot "maps" "$Name@$versionPattern.json"
        if (Test-Path $testPath) {
            Write-Verbose "Loading module-specific redirect map from: $testPath"
            $moduleMap = Get-Content $testPath -Raw | ConvertFrom-Json -AsHashtable
            $script:moduleMapCache[$cacheKey] = $moduleMap
            break
        }
    }
    
    if ($moduleMap) {
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
    Builds a dependency graph by recursively querying a remote repository via Find-PSResource.
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
    
    $notFound = $false
    if (-not $moduleInfo) {
        Write-Verbose "${indent}Module not found in repository: $ModuleName version $ModuleVersion (will validate after resolution)"
        $notFound = $true
    }
    
    Write-Verbose "${indent}Building graph for: $ModuleName version $ModuleVersion"
    
    $graphNode = [DependencyGraphNode]::new(
        $ModuleName,
        $ModuleVersion,
        [System.Collections.ArrayList]@(),
        $notFound,
        $(if ($moduleInfo) { $moduleInfo.Repository } else { $null }),
        $null
    )
    $Graph[$moduleKey] = $graphNode
    
    if ($notFound) {
        return
    }
    
    $deps = $moduleInfo.Dependencies
    if (-not $deps -or $deps.Count -eq 0) {
        Write-Verbose "${indent}No dependencies for $ModuleName"
        return
    }
    
    Write-Verbose "${indent}Found $($deps.Count) dependency(ies)"
    
    foreach ($dep in $deps) {
        $depName = $dep.Name
        $depVersion = $dep.VersionRange
        
        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
            -RedirectMap $RedirectMap -Indent $indent
        
        $resolvedDepVersion = $redirectResult.ResolvedVersion
        $resolvedDepName = $redirectResult.ResolvedName
        
        $depKey = "${resolvedDepName}@${resolvedDepVersion}"
        Write-Verbose "${indent}  Dependency: $depKey"
        
        [void]$graphNode.Dependencies.Add($depKey)
        
        $depRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $resolvedDepName -Version $resolvedDepVersion
        
        Build-RemoteDependencyGraph -ModuleName $resolvedDepName -ModuleVersion $resolvedDepVersion `
            -Graph $Graph -RedirectMap $depRedirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease -Depth ($Depth + 1)
    }
}

<#
.SYNOPSIS
    Compares two semver strings including prerelease labels.
    Returns -1, 0, or 1. Prerelease < release (1.0.0-alpha < 1.0.0).
#>
function Compare-SemVer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version1,
        
        [Parameter(Mandatory = $true)]
        [string]$Version2
    )
    
    $v1Parts = $Version1 -split '-', 2
    $v2Parts = $Version2 -split '-', 2
    
    $v1Base = $v1Parts[0]
    $v2Base = $v2Parts[0]
    $v1Prerelease = if ($v1Parts.Count -gt 1) { $v1Parts[1] } else { $null }
    $v2Prerelease = if ($v2Parts.Count -gt 1) { $v2Parts[1] } else { $null }
    
    try {
        $v1Ver = [System.Version]$v1Base
        $v2Ver = [System.Version]$v2Base
        $baseCompare = $v1Ver.CompareTo($v2Ver)
    }
    catch {
        $baseCompare = [string]::Compare($v1Base, $v2Base, [StringComparison]::OrdinalIgnoreCase)
    }
    
    if ($baseCompare -ne 0) {
        return $baseCompare
    }
    
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
    
    # Both have prerelease — lexicographic: alpha < beta < dev < rc
    return [string]::Compare($v1Prerelease, $v2Prerelease, [StringComparison]::OrdinalIgnoreCase)
}

<#
.SYNOPSIS
    Resolves diamond dependencies — selects the highest found version and updates all graph references.
#>
function Resolve-DiamondDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph
    )
    
    # Group nodes by module name
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
            NotFound = $node.NotFound
        }
    }
    
    # Resolve conflicts — prefer found versions, then highest semver
    foreach ($moduleName in $moduleVersions.Keys) {
        $versions = $moduleVersions[$moduleName]
        if ($versions.Count -gt 1) {
            $sorted = $versions | Sort-Object -Property @{
                Expression = {
                    if ($_.NotFound) { "1" } else { "0" }
                }
            }, @{
                Expression = {
                    $ver = $_.VersionString
                    $parts = $ver -split '-', 2
                    $base = $parts[0]
                    $prerelease = if ($parts.Count -gt 1) { $parts[1] } else { $null }
                    
                    $verParts = $base -split '\.'
                    $paddedBase = ($verParts | ForEach-Object { $_.PadLeft(10, '0') }) -join '.'
                    
                    # Release versions sort after prereleases
                    $prereleaseKey = if ($null -eq $prerelease) { 'zzzzzzzzzz' } else { $prerelease }
                    
                    "$paddedBase|$prereleaseKey"
                }
                Descending = $true
            }
            
            $highest = $sorted[0]
            $conflicts = $sorted | Select-Object -Skip 1
            
            $discardedNotFound = $conflicts | Where-Object { $_.NotFound }
            if ($discardedNotFound) {
                Write-Verbose "  Discarding unavailable version(s): $($discardedNotFound.VersionString -join ', ') (higher version available)"
            }
            
            Write-Warning "Diamond dependency detected for '$moduleName': versions $($versions.VersionString -join ', '). Using highest available: $($highest.VersionString)"
            
            foreach ($conflict in $conflicts) {
                $oldKey = $conflict.Key
                $newKey = $highest.Key
                
                Write-Verbose "  Redirecting $oldKey -> $newKey"
                
                # Update all references from old version to new
                foreach ($nodeKey in $Graph.Keys) {
                    $node = $Graph[$nodeKey]
                    for ($i = 0; $i -lt $node.Dependencies.Count; $i++) {
                        if ($node.Dependencies[$i] -eq $oldKey) {
                            $node.Dependencies[$i] = $newKey
                        }
                    }
                }
                
                $Graph.Remove($oldKey)
            }
        }
    }
    
    # Validate all remaining nodes were found
    foreach ($nodeKey in $Graph.Keys) {
        $node = $Graph[$nodeKey]
        if ($node.NotFound) {
            throw "Module not found in repository: $($node.Name) version $($node.Version). No alternative version available to satisfy the dependency."
        }
    }
}

<#
.SYNOPSIS
    Returns module keys in topological order (dependencies first). Warns on cycles.
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
    Builds a dependency graph for installed modules via Get-PSResource.
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
    
    $notFound = $false
    if (-not $installedModule) {
        Write-Verbose "${indent}Module not installed: $ModuleName version $ModuleVersion (will validate after resolution)"
        $notFound = $true
    }
    
    $actualVersion = if ($installedModule) { $installedModule.Version.ToString() } else { $ModuleVersion }
    Write-Verbose "${indent}Building graph for: $ModuleName version $actualVersion"
    
    # InstalledLocation is the base modules folder; append ModuleName/Version
    $moduleVersionPath = if ($installedModule) { Join-Path $installedModule.InstalledLocation $ModuleName $actualVersion } else { $null }
    
    $graphNode = [DependencyGraphNode]::new(
        $ModuleName,
        $actualVersion,
        [System.Collections.ArrayList]@(),
        $notFound,
        $null,
        $moduleVersionPath
    )
    $Graph[$moduleKey] = $graphNode
    
    if ($notFound) {
        return
    }
    
    $deps = $installedModule.Dependencies
    if (-not $deps -or $deps.Count -eq 0) {
        Write-Verbose "${indent}No dependencies for $ModuleName"
        return
    }
    
    Write-Verbose "${indent}Found $($deps.Count) dependency(ies)"
    
    foreach ($dep in $deps) {
        $depName = $dep.Name
        $depVersion = $dep.VersionRange
        
        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
            -RedirectMap $RedirectMap -Indent $indent
        
        $resolvedDepVersion = $redirectResult.ResolvedVersion
        $resolvedDepName = $redirectResult.ResolvedName
        
        $depKey = "${resolvedDepName}@${resolvedDepVersion}"
        Write-Verbose "${indent}  Dependency: $depKey"
        
        [void]$graphNode.Dependencies.Add($depKey)
        
        $depRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $resolvedDepName -Version $resolvedDepVersion
        
        Build-InstalledDependencyGraph -ModuleName $resolvedDepName -ModuleVersion $resolvedDepVersion `
            -Graph $Graph -RedirectMap $depRedirectMap -Depth ($Depth + 1)
    }
}

function Install-PSResourcePinned {
    <#
    .SYNOPSIS
        Installs a module with pinned dependency versions.
        Works around PowerCLI not following semver (13.4 breaks backward-compat).
        
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
    
    # Load redirect map
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
    
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-RemoteDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
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
        Downloads a module and dependencies as NuGet packages with pinned versions.
        
    .EXAMPLE
        Save-PSResourcePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0" -Path "./packages"
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
    
    # Validate and create destination path
    if (-not (Test-Path $Path)) {
        Write-Verbose "Creating destination directory: $Path"
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $resolvedPath = Resolve-Path $Path
    Write-Verbose "Saving packages to: $resolvedPath"
    
    # Load redirect map
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
    
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-RemoteDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
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

<#
.SYNOPSIS
    Extracts RequiredModules and ModuleList from a manifest, deduped (RequiredModules wins).
    NuGet feeds package both as dependencies; reading both keeps the local graph consistent
    with remote graphs and prevents "assembly already loaded" errors during pre-loading.

.OUTPUTS
    Array of @{ Name; Version } hashtables.
#>
function Get-ManifestModuleDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest
    )

    $hasRequired = $Manifest.ContainsKey('RequiredModules') -and $Manifest.RequiredModules -and $Manifest.RequiredModules.Count -gt 0
    $hasModuleList = $Manifest.ContainsKey('ModuleList') -and $Manifest.ModuleList -and $Manifest.ModuleList.Count -gt 0

    if (-not $hasRequired -and -not $hasModuleList) {
        return @()
    }

    # Parse a single manifest entry into @{ Name; Version }
    function ParseEntry {
        param([object]$Entry, [string]$Source)

        if ($Entry -is [string]) {
            throw "$Source entry '$Entry' has no version. All entries must specify a version (RequiredVersion or ModuleVersion)."
        }
        elseif ($Entry -is [hashtable]) {
            $name = if ($Entry.ContainsKey('ModuleName')) { $Entry.ModuleName } else { $null }
            if (-not $name) {
                throw "$Source entry has no module name: $($Entry | ConvertTo-Json -Compress)"
            }
            $version = $null
            if ($Entry.ContainsKey('RequiredVersion')) {
                $version = $Entry.RequiredVersion.ToString()
            }
            elseif ($Entry.ContainsKey('ModuleVersion')) {
                $version = "[$($Entry.ModuleVersion), )"
            }
            if (-not $version) {
                throw "$Source entry '$name' has no version. All entries must specify a version (RequiredVersion or ModuleVersion)."
            }
            return @{ Name = $name; Version = $version }
        }
        else {
            throw "Unrecognized $Source format in manifest: $Entry. Expected string or hashtable."
        }
    }

    # RequiredModules take precedence
    $seen = @{}
    $results = [System.Collections.ArrayList]@()

    if ($hasRequired) {
        Write-Verbose "Found $($Manifest.RequiredModules.Count) module(s) in RequiredModules"
        foreach ($entry in $Manifest.RequiredModules) {
            $parsed = ParseEntry -Entry $entry -Source 'RequiredModules'
            $key = $parsed.Name.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                [void]$results.Add($parsed)
            }
        }
    }

    if ($hasModuleList) {
        Write-Verbose "Found $($Manifest.ModuleList.Count) module(s) in ModuleList"
        foreach ($entry in $Manifest.ModuleList) {
            $parsed = ParseEntry -Entry $entry -Source 'ModuleList'
            $key = $parsed.Name.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                [void]$results.Add($parsed)
            }
            else {
                Write-Verbose "Skipping ModuleList entry '$($parsed.Name)' — already declared in RequiredModules"
            }
        }
    }

    return $results.ToArray()
}

function Find-PSResourceDependencies {
    <#
    .SYNOPSIS
        Resolves all dependencies (RequiredModules + ModuleList) from a .psd1 manifest via remote repository.
        
    .EXAMPLE
        Find-PSResourceDependencies -ManifestPath "./MyModule/MyModule.psd1"
        
    .OUTPUTS
        Array of PSCustomObject with Name, Version, Repository, and IsRedirected properties.
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
    
    if (-not (Test-Path $ManifestPath)) {
        throw "Manifest file not found: $ManifestPath"
    }
    
    $resolvedPath = Resolve-Path $ManifestPath
    if (-not $resolvedPath.Path.EndsWith('.psd1')) {
        throw "File must be a PowerShell module manifest (.psd1): $ManifestPath"
    }
    
    Write-Verbose "Reading manifest from: $resolvedPath"
    
    $manifest = Import-PowerShellDataFile -Path $resolvedPath
    
    $moduleDependencies = @(Get-ManifestModuleDependencies -Manifest $manifest)
    if ($moduleDependencies.Count -eq 0) {
        Write-Verbose "No module dependencies found in manifest (RequiredModules or ModuleList)"
        return @()
    }
    
    $manifestModuleName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPath.Path)
    $manifestModuleVersion = if ($manifest.ModuleVersion) { $manifest.ModuleVersion.ToString() } else { "" }
    
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Looking for redirect map based on manifest: $manifestModuleName version $manifestModuleVersion"
        $redirectMap = Get-MergedRedirectMap -OuterMap $script:defaultRedirectMap -Name $manifestModuleName -Version $manifestModuleVersion
    }
    
    Write-Verbose "Found $($moduleDependencies.Count) module dependency(ies) in manifest"
    
    $dependencyGraph = @{}
    
    foreach ($depEntry in $moduleDependencies) {
        $moduleName = $depEntry.Name
        $moduleVersion = $depEntry.Version
        
        $mergedRedirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $moduleName -Version ($moduleVersion ?? "")
        $redirectResult = Find-DependencyRedirect -DependencyName $moduleName -DependencyVersion $moduleVersion `
            -RedirectMap $mergedRedirectMap -Indent ""
        
        Build-RemoteDependencyGraph -ModuleName $redirectResult.ResolvedName -ModuleVersion $redirectResult.ResolvedVersion `
            -Graph $dependencyGraph -RedirectMap $mergedRedirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    }
    
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
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
        Installs all manifest dependencies using Find-PSResourceDependencies.
        
    .EXAMPLE
        Install-PSResourceDependencies -ManifestPath "./MyModule/MyModule.psd1"
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
    
    foreach ($dependency in $resolvedDependencies) {
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

function Import-PSResourceDependencies {
    <#
    .SYNOPSIS
        Imports all manifest dependencies (RequiredModules + ModuleList) in topological order
        with pinned versions. Prevents "assembly already loaded" errors from incomplete graphs.
        
    .EXAMPLE
        Import-PSResourceDependencies -ManifestPath "./MyModule/MyModule.psd1"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
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
    
    # Extract module dependencies from both RequiredModules and ModuleList
    $moduleDependencies = @(Get-ManifestModuleDependencies -Manifest $manifest)
    if ($moduleDependencies.Count -eq 0) {
        Write-Verbose "No module dependencies found in manifest (RequiredModules or ModuleList)"
        return
    }
    
    $manifestModuleName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedPath.Path)
    $manifestModuleVersion = if ($manifest.ModuleVersion) { $manifest.ModuleVersion.ToString() } else { "" }
    
    if ($RedirectMapPath) {
        if (-not (Test-Path $RedirectMapPath)) {
            throw "Redirect map file not found: $RedirectMapPath"
        }
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Looking for redirect map based on manifest: $manifestModuleName version $manifestModuleVersion"
        $redirectMap = Get-MergedRedirectMap -OuterMap $script:defaultRedirectMap -Name $manifestModuleName -Version $manifestModuleVersion
    }
    
    Write-Verbose "Found $($moduleDependencies.Count) module dependency(ies) in manifest"
    
    $dependencyGraph = @{}
    
    foreach ($depEntry in $moduleDependencies) {
        $moduleName = $depEntry.Name
        $moduleVersion = $depEntry.Version
        
        $mergedRedirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $moduleName -Version ($moduleVersion ?? "")
        $redirectResult = Find-DependencyRedirect -DependencyName $moduleName -DependencyVersion $moduleVersion `
            -RedirectMap $mergedRedirectMap -Indent ""
        
        Build-InstalledDependencyGraph -ModuleName $redirectResult.ResolvedName -ModuleVersion $redirectResult.ResolvedVersion `
            -Graph $dependencyGraph -RedirectMap $mergedRedirectMap
    }
    
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    # Compute topological order
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
        
        $loadedModule = Get-Module -Name $modName | Where-Object { $_.Version.ToString() -eq $modVersion }
        
        if ($loadedModule -and -not $Force) {
            Write-Verbose "Already loaded: $modName version $modVersion"
            $importedModules[$moduleKey] = $loadedModule
            continue
        }
        
        # -Global ensures modules persist after this function returns
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
    
    Write-Verbose "Successfully imported $($importedModules.Count) module(s) from manifest"
    
    if ($PassThru) {
        return $importedModules.Values
    }
}

function Import-ModulePinned {
    <#
    .SYNOPSIS
        Imports a module after pre-loading ALL transitive dependencies at exact versions.
        Prevents PowerShell from loading wrong versions via minimum-version semantics.
        
    .EXAMPLE
        Import-ModulePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0"
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
    
    # Load redirect map
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
    
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-InstalledDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap
    
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
    
    # Compute topological order
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
        
        $loadedModule = Get-Module -Name $modName | Where-Object { $_.Version.ToString() -eq $modVersion }
        
        if ($loadedModule -and -not $Force) {
            Write-Verbose "Already loaded: $modName version $modVersion"
            $importedModules[$moduleKey] = $loadedModule
            continue
        }
        
        # -Global ensures modules persist after this function returns
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
    
    $mainModuleKey = "${Name}@${RequiredVersion}"
    $mainModule = $importedModules[$mainModuleKey]
    
    if (-not $mainModule) {
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
        Resolves a module and all dependencies with pinned versions. Returns results in topological order.
        
    .EXAMPLE
        Find-PSResourcesPinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0"
        
    .OUTPUTS
        Array of objects with Name, Version, Repository, and Dependencies properties.
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
    
    # Load redirect map
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
    
    $redirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $Name -Version $RequiredVersion
    
    Write-Verbose "Building dependency graph for $Name version $RequiredVersion"
    $dependencyGraph = @{}
    
    Build-RemoteDependencyGraph -ModuleName $Name -ModuleVersion $RequiredVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential -Prerelease:$Prerelease
    
    Resolve-DiamondDependencies -Graph $dependencyGraph
    
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph)
    
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