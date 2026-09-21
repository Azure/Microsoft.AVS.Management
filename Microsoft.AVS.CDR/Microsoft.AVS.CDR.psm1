$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

class DependencyGraphNode {
    [string]$Name
    [string]$Version
    [System.Collections.ArrayList]$Dependencies
    [System.Collections.ArrayList]$Constraints
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
        $this.Constraints = [System.Collections.ArrayList]::new()
        $this.NotFound = $NotFound
        $this.Repository = $Repository
        $this.InstalledLocation = $InstalledLocation
    }
}

function Get-ConcreteVersionConstraint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    return @{
        OriginalSpec   = $Version
        Minimum        = $Version
        Maximum        = $Version
        IncludeMinimum = $true
        IncludeMaximum = $true
        IsExact        = $true
        IsHardPin      = $true
        ConcretePin    = $Version
    }
}

function Merge-DependencyConstraint {
    param(
        [Parameter(Mandatory = $true)]
        [DependencyGraphNode]$Node,

        [Parameter(Mandatory = $true)]
        [hashtable]$Constraint
    )

    $duplicate = $Node.Constraints | Where-Object {
        $_.OriginalSpec -eq $Constraint.OriginalSpec -and
        $_.IsHardPin -eq $Constraint.IsHardPin -and
        $_.ConcretePin -eq $Constraint.ConcretePin
    }
    if (-not $duplicate) {
        [void]$Node.Constraints.Add($Constraint)
    }
}

$script:defaultRedirectMap = @{
}

$script:moduleMapCache = @{
}

<#
.SYNOPSIS
    Parses a version specification into its exactness and normalized concrete
    version. Mirrors NuGet range notation: "[1.0, 1.0]" is exact (one concrete
    version) while open-ended or unequal-endpoint ranges are not.

.OUTPUTS
    Hashtable describing exactness and NuGet range bounds.
#>
function Get-NormalizedVersionSpec {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Version
    )

    $isExact = $true
    $normalized = $Version
    $minimum = $Version
    $maximum = $Version
    $includeMinimum = $true
    $includeMaximum = $true

    # NuGet singleton exact range: "[1.0]"
    if ($Version -match '^\[\s*([^,\[\]]+?)\s*\]$') {
        $normalized = $matches[1]
        $minimum = $normalized
        $maximum = $normalized
    }
    # Version range like "[1.0, 1.0]", "[1.0, )", "(, 2.0]"
    elseif ($Version -match '^(\[|\()([^,]*),\s*([^\]\)]*)(\]|\))$') {
        $openBracket = $matches[1]
        $minVer = $matches[2]
        $maxVer = $matches[3]
        $closeBracket = $matches[4]

        if ($minVer -and $maxVer -and ($minVer -eq $maxVer) -and ($openBracket -eq '[') -and ($closeBracket -eq ']')) {
            $normalized = $minVer  # exact: [1.0, 1.0]
            $minimum = $minVer
            $maximum = $maxVer
        }
        else {
            $isExact = $false
            $normalized = $minVer
            $minimum = $minVer
            $maximum = $maxVer
            $includeMinimum = $openBracket -eq '['
            $includeMaximum = $closeBracket -eq ']'
        }
    }

    return @{
        IsExact        = $isExact
        Normalized     = $normalized
        Minimum        = $minimum
        Maximum        = $maximum
        IncludeMinimum = $includeMinimum
        IncludeMaximum = $includeMaximum
    }
}

function Test-VersionSatisfiesConstraint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [hashtable]$Constraint
    )

    if ($Constraint.IsHardPin -and $Constraint.ConcretePin) {
        return Test-EquivalentConcreteVersion -Version1 $Version -Version2 $Constraint.ConcretePin
    }

    if ($Constraint.Minimum) {
        $minimumComparison = Compare-SemVer -Version1 $Version -Version2 $Constraint.Minimum
        if ($minimumComparison -lt 0 -or ($minimumComparison -eq 0 -and (-not $Constraint.IncludeMinimum))) {
            return $false
        }
    }

    if ($Constraint.Maximum) {
        $maximumComparison = Compare-SemVer -Version1 $Version -Version2 $Constraint.Maximum
        if ($maximumComparison -gt 0 -or ($maximumComparison -eq 0 -and (-not $Constraint.IncludeMaximum))) {
            return $false
        }
    }

    return $true
}

function Test-EquivalentConcreteVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version1,

        [Parameter(Mandatory = $true)]
        [string]$Version2
    )

    $parts1 = $Version1 -split '-', 2
    $parts2 = $Version2 -split '-', 2
    $prerelease1 = if ($parts1.Count -gt 1) { $parts1[1] } else { $null }
    $prerelease2 = if ($parts2.Count -gt 1) { $parts2[1] } else { $null }

    if (-not [string]::Equals($prerelease1, $prerelease2, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    try {
        $version1Parts = @([version]$parts1[0]).Major, @([version]$parts1[0]).Minor,
            @([version]$parts1[0]).Build, @([version]$parts1[0]).Revision
        $version2Parts = @([version]$parts2[0]).Major, @([version]$parts2[0]).Minor,
            @([version]$parts2[0]).Build, @([version]$parts2[0]).Revision

        for ($index = 0; $index -lt 4; $index++) {
            $left = if ($version1Parts[$index] -lt 0) { 0 } else { $version1Parts[$index] }
            $right = if ($version2Parts[$index] -lt 0) { 0 } else { $version2Parts[$index] }
            if ($left -ne $right) {
                return $false
            }
        }
        return $true
    }
    catch {
        return [string]::Equals($parts1[0], $parts2[0], [StringComparison]::OrdinalIgnoreCase)
    }
}

function Test-ConcreteVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    return $Version -match '^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
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
        [string]$Indent = "",

        [Parameter(Mandatory = $false)]
        [switch]$DependencyVersionIsRange
    )
    
    if ([string]::IsNullOrWhiteSpace($DependencyVersion)) {
        if ($RedirectMap.ContainsKey($DependencyName)) {
            $depVersion = $RedirectMap[$DependencyName].Trim()
            if ($depVersion -eq "*" -or (-not (Test-ConcreteVersion -Version $depVersion))) {
                throw "${Indent}Redirect for unversioned dependency '$DependencyName' must specify a concrete version."
            }
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
                IsHardPin = $true
                Constraint = Get-ConcreteVersionConstraint -Version $depVersion
            }
        }
        else {
            throw "${Indent}Cannot conservatively resolve version for dependency '$DependencyName'. Please add a redirect mapping for this module."
        }
    }
    
    $depSpec = Get-NormalizedVersionSpec -Version $DependencyVersion
    $isExactVersion = $depSpec.IsExact
    $normalizedDepVersion = $depSpec.Normalized

    # PSResource dependency VersionRange uses a bare version as an inclusive
    # minimum. Top-level RequiredVersion values use the same spelling for an
    # exact requirement, so callers must identify dependency-range metadata.
    if ($DependencyVersionIsRange -and $DependencyVersion -notmatch '^(\[|\()') {
        $isExactVersion = $false
        $depSpec.Minimum = $DependencyVersion
        $depSpec.Maximum = $null
        $depSpec.IncludeMinimum = $true
        $depSpec.IncludeMaximum = $false
    }

    $constraint = @{
        OriginalSpec   = $DependencyVersion
        Minimum        = $depSpec.Minimum
        Maximum        = $depSpec.Maximum
        IncludeMinimum = $depSpec.IncludeMinimum
        IncludeMaximum = $depSpec.IncludeMaximum
        IsExact        = $isExactVersion
        IsHardPin      = $isExactVersion
        ConcretePin    = $normalizedDepVersion
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
        $resolvedVersion = $matchedEntry.Value.Trim()
        
        # "*" retains version but normalizes dependency name casing
        if ($resolvedVersion -eq "*") {
            if ((-not $isExactVersion) -and
                ((-not $constraint.Minimum) -or (-not $constraint.IncludeMinimum))) {
                throw "${Indent}Cannot conservatively resolve dependency '$DependencyName' range '$DependencyVersion' without an inclusive minimum. Please add an explicit redirect mapping for this module."
            }
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
                IsHardPin = $isExactVersion
                Constraint = $constraint
            }
        }

        if (-not (Test-ConcreteVersion -Version $resolvedVersion)) {
            throw "${Indent}Redirect target for '$DependencyName' must specify a concrete version; received '$resolvedVersion'."
        }
        
        if ($isExactVersion -and
            (-not (Test-EquivalentConcreteVersion -Version1 $resolvedVersion -Version2 $normalizedDepVersion))) {
            throw "${Indent}Cannot redirect exact version dependency '$DependencyName' from version $normalizedDepVersion to $resolvedVersion. Exact version specifications must redirect to the same version or have no redirect."
        }

        if ((-not $isExactVersion) -and
            (-not (Test-VersionSatisfiesConstraint -Version $resolvedVersion -Constraint $constraint))) {
            throw "${Indent}Redirect target '$resolvedVersion' does not satisfy dependency range '$DependencyVersion' for '$DependencyName'."
        }

        $constraint.IsHardPin = $true
        $constraint.ConcretePin = $resolvedVersion
        
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
            IsHardPin = $true
            Constraint = $constraint
        }
    }
    else {
        if ((-not $isExactVersion) -and
            ((-not $constraint.Minimum) -or (-not $constraint.IncludeMinimum))) {
            throw "${Indent}Cannot conservatively resolve dependency '$DependencyName' range '$DependencyVersion' without an inclusive minimum. Please add an explicit redirect mapping for this module."
        }

        $constraint.ConcretePin = $normalizedDepVersion
        return @{
            ResolvedVersion = $normalizedDepVersion
            ResolvedName = $DependencyName
            IsRedirected = $false
            IsHardPin = $isExactVersion
            Constraint = $constraint
        }
    }
}

function Resolve-ExactDependency {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion,

        [Parameter(Mandatory = $true)]
        [hashtable]$RedirectMap
    )

    $specification = Get-NormalizedVersionSpec -Version $RequiredVersion
    if (-not $specification.IsExact) {
        throw "RequiredVersion must identify one exact version; '$RequiredVersion' is a range."
    }

    return Find-DependencyRedirect -DependencyName $Name -DependencyVersion $RequiredVersion `
        -RedirectMap $RedirectMap
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
        [int]$Depth = 0,

        [Parameter(Mandatory = $false)]
        [hashtable]$Constraint
    )
    
    $indent = "  " * $Depth
    if (-not $Constraint) {
        $Constraint = Get-ConcreteVersionConstraint -Version $ModuleVersion
    }
    $moduleKey = "${ModuleName}@${ModuleVersion}"
    if ($Graph.ContainsKey($moduleKey)) {
        Merge-DependencyConstraint -Node $Graph[$moduleKey] -Constraint $Constraint
        Write-Verbose "${indent}Already in graph: $moduleKey"
        return $moduleKey
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

    $actualVersion = if ($moduleInfo) {
        $version = $moduleInfo.Version.ToString()
        $prereleaseProperty = $moduleInfo.PSObject.Properties['Prerelease']
        if ($prereleaseProperty -and $prereleaseProperty.Value) {
            "$version-$($prereleaseProperty.Value)"
        }
        else {
            $version
        }
    }
    else {
        $ModuleVersion
    }

    if ($moduleInfo -and (-not (Test-EquivalentConcreteVersion -Version1 $actualVersion -Version2 $ModuleVersion))) {
        throw "Module '$ModuleName' resolved to version $actualVersion instead of concrete pin $ModuleVersion."
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
    Merge-DependencyConstraint -Node $graphNode -Constraint $Constraint
    
    if ($notFound) {
        return $moduleKey
    }
    
    $deps = $moduleInfo.Dependencies
    if (-not $deps -or $deps.Count -eq 0) {
        Write-Verbose "${indent}No dependencies for $ModuleName"
        return $moduleKey
    }
    
    Write-Verbose "${indent}Found $($deps.Count) dependency(ies)"
    $effectiveRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $ModuleName -Version $ModuleVersion
    
    foreach ($dep in $deps) {
        $depName = $dep.Name
        $depVersion = $dep.VersionRange
        
        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
            -RedirectMap $effectiveRedirectMap -Indent $indent -DependencyVersionIsRange
        
        $resolvedDepVersion = $redirectResult.ResolvedVersion
        $resolvedDepName = $redirectResult.ResolvedName
        
        $depKey = Build-RemoteDependencyGraph -ModuleName $resolvedDepName -ModuleVersion $resolvedDepVersion `
            -Graph $Graph -RedirectMap $effectiveRedirectMap -Repository $Repository -Credential $Credential `
            -Prerelease:$Prerelease -Depth ($Depth + 1) -Constraint $redirectResult.Constraint
        Write-Verbose "${indent}  Dependency: $depKey"
        
        if (-not $graphNode.Dependencies.Contains($depKey)) {
            [void]$graphNode.Dependencies.Add($depKey)
        }
    }

    return $moduleKey
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
        $v1Components = $v1Ver.Major, $v1Ver.Minor, $v1Ver.Build, $v1Ver.Revision
        $v2Components = $v2Ver.Major, $v2Ver.Minor, $v2Ver.Build, $v2Ver.Revision
        $baseCompare = 0
        for ($componentIndex = 0; $componentIndex -lt 4; $componentIndex++) {
            $component1 = if ($v1Components[$componentIndex] -lt 0) { 0 } else { $v1Components[$componentIndex] }
            $component2 = if ($v2Components[$componentIndex] -lt 0) { 0 } else { $v2Components[$componentIndex] }
            if ($component1 -ne $component2) {
                $baseCompare = $component1.CompareTo($component2)
                break
            }
        }
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
    
    $identifiers1 = $v1Prerelease -split '\.'
    $identifiers2 = $v2Prerelease -split '\.'
    $identifierCount = [Math]::Max($identifiers1.Count, $identifiers2.Count)

    for ($index = 0; $index -lt $identifierCount; $index++) {
        if ($index -ge $identifiers1.Count) {
            return -1
        }
        if ($index -ge $identifiers2.Count) {
            return 1
        }

        $identifier1 = $identifiers1[$index]
        $identifier2 = $identifiers2[$index]
        $isNumeric1 = $identifier1 -match '^\d+$'
        $isNumeric2 = $identifier2 -match '^\d+$'

        if ($isNumeric1 -and $isNumeric2) {
            $number1 = $identifier1.TrimStart('0')
            $number2 = $identifier2.TrimStart('0')
            if ($number1.Length -eq 0) {
                $number1 = "0"
            }
            if ($number2.Length -eq 0) {
                $number2 = "0"
            }
            if ($number1.Length -ne $number2.Length) {
                return $number1.Length.CompareTo($number2.Length)
            }
            $numericComparison = [string]::Compare($number1, $number2, [StringComparison]::Ordinal)
            if ($numericComparison -ne 0) {
                return $numericComparison
            }
        }
        elseif ($isNumeric1 -ne $isNumeric2) {
            if ($isNumeric1) {
                return -1
            }
            return 1
        }
        else {
            $identifierComparison = [string]::Compare(
                $identifier1,
                $identifier2,
                [StringComparison]::OrdinalIgnoreCase
            )
            if ($identifierComparison -ne 0) {
                return $identifierComparison
            }
        }
    }

    return 0
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
    
    $redirectedKeys = @{}

    # Resolve conflicts by choosing the lowest found candidate satisfying every
    # incoming constraint. Exact and redirect pins are hard requirements.
    foreach ($moduleName in $moduleVersions.Keys) {
        $versions = $moduleVersions[$moduleName]
        if ($versions.Count -gt 1) {
            $constraints = [System.Collections.ArrayList]@()
            foreach ($version in $versions) {
                if ($version.Node.Constraints.Count -eq 0) {
                    [void]$constraints.Add(@{
                        OriginalSpec   = "[$($version.VersionString), )"
                        Minimum        = $version.VersionString
                        Maximum        = $null
                        IncludeMinimum = $true
                        IncludeMaximum = $false
                        IsExact        = $false
                        IsHardPin      = $false
                        ConcretePin    = $version.VersionString
                    })
                }
                else {
                    foreach ($constraint in $version.Node.Constraints) {
                        [void]$constraints.Add($constraint)
                    }
                }
            }

            $hardPins = [System.Collections.ArrayList]@()
            foreach ($pin in @($constraints | Where-Object IsHardPin | Select-Object -ExpandProperty ConcretePin)) {
                $equivalentPin = $hardPins | Where-Object {
                    Test-EquivalentConcreteVersion -Version1 $_ -Version2 $pin
                }
                if (-not $equivalentPin) {
                    [void]$hardPins.Add($pin)
                }
            }
            if ($hardPins.Count -gt 1) {
                throw "Conflicting hard pins for '$moduleName': $($hardPins -join ', ')."
            }

            $foundCandidates = @($versions | Where-Object { -not $_.NotFound })
            if ($foundCandidates.Count -eq 0) {
                throw "Module not found: $moduleName versions $($versions.VersionString -join ', '). No available version satisfies the dependency."
            }

            $selected = $null
            foreach ($candidate in $foundCandidates) {
                if ($hardPins.Count -eq 1 -and
                    (-not (Test-EquivalentConcreteVersion -Version1 $candidate.VersionString -Version2 $hardPins[0]))) {
                    continue
                }

                $satisfiesAll = $true
                foreach ($constraint in $constraints) {
                    if (-not (Test-VersionSatisfiesConstraint -Version $candidate.VersionString -Constraint $constraint)) {
                        $satisfiesAll = $false
                        break
                    }
                }

                if ($satisfiesAll -and
                    ($null -eq $selected -or
                    (Compare-SemVer -Version1 $candidate.VersionString -Version2 $selected.VersionString) -lt 0)) {
                    $selected = $candidate
                }
            }

            if (-not $selected) {
                throw "No version of '$moduleName' satisfies all dependency constraints: $($constraints.OriginalSpec -join ', ')."
            }

            $conflicts = $versions | Where-Object { $_.Key -ne $selected.Key }
            Write-Warning "Diamond dependency detected for '$moduleName': versions $($versions.VersionString -join ', '). Using lowest compatible: $($selected.VersionString)"

            foreach ($constraint in $constraints) {
                Merge-DependencyConstraint -Node $selected.Node -Constraint $constraint
            }

            foreach ($conflict in $conflicts) {
                $oldKey = $conflict.Key
                $newKey = $selected.Key
                $redirectedKeys[$oldKey] = $newKey
                
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
            throw "Module not found: $($node.Name) version $($node.Version). No alternative version available to satisfy the dependency."
        }
    }

    return $redirectedKeys
}

function Resolve-GraphRootKey {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RootKeys,

        [Parameter(Mandatory = $true)]
        [hashtable]$RedirectedKeys
    )

    return @($RootKeys | ForEach-Object {
        $resolvedKey = $_
        while ($RedirectedKeys.ContainsKey($resolvedKey)) {
            $resolvedKey = $RedirectedKeys[$resolvedKey]
        }
        $resolvedKey
    })
}

<#
.SYNOPSIS
    Returns module keys in topological order (dependencies first). Warns on cycles.
    Traversal is anchored on -RootKeys (in given order) then a sorted pass over the
    rest, so the order is deterministic and follows each node's reported dependency
    order (matching native Import-Module's RequiredModules array-order walk).
#>
function Get-TopologicalOrder {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph,

        [Parameter(Mandatory = $false)]
        [string[]]$RootKeys
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

    # Anchor on the declared roots (in order), then a deterministic sorted pass over the rest.
    if ($RootKeys) {
        foreach ($rootKey in $RootKeys) {
            if ($Graph.ContainsKey($rootKey)) {
                Visit -NodeKey $rootKey
            }
        }
    }

    foreach ($nodeKey in ($Graph.Keys | Sort-Object)) {
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
        [int]$Depth = 0,

        [Parameter(Mandatory = $false)]
        [hashtable]$Constraint
    )
    
    $indent = "  " * $Depth
    if (-not $Constraint) {
        $Constraint = Get-ConcreteVersionConstraint -Version $ModuleVersion
    }
    $moduleKey = "${ModuleName}@${ModuleVersion}"
    if ($Graph.ContainsKey($moduleKey)) {
        Merge-DependencyConstraint -Node $Graph[$moduleKey] -Constraint $Constraint
        Write-Verbose "${indent}Already in graph: $moduleKey"
        return $moduleKey
    }

    # Find the installed module
    $installedModule = Get-PSResource -Name $ModuleName -Version $ModuleVersion -ErrorAction SilentlyContinue | Select-Object -First 1
    
    $notFound = $false
    if (-not $installedModule) {
        Write-Verbose "${indent}Module not installed: $ModuleName version $ModuleVersion (will validate after resolution)"
        $notFound = $true
    }
    
    $actualVersion = if ($installedModule) {
        $version = $installedModule.Version.ToString()
        $prereleaseProperty = $installedModule.PSObject.Properties['Prerelease']
        if ($prereleaseProperty -and $prereleaseProperty.Value) {
            "$version-$($prereleaseProperty.Value)"
        }
        else {
            $version
        }
    }
    else {
        $ModuleVersion
    }

    if ($installedModule -and (-not (Test-EquivalentConcreteVersion -Version1 $actualVersion -Version2 $ModuleVersion))) {
        throw "Installed module '$ModuleName' resolved to version $actualVersion instead of concrete pin $ModuleVersion."
    }
    Write-Verbose "${indent}Building graph for: $ModuleName version $ModuleVersion"
    
    # InstalledLocation is the base modules folder; append ModuleName/Version
    $moduleVersionPath = if ($installedModule) {
        Join-Path $installedModule.InstalledLocation $ModuleName $installedModule.Version.ToString()
    }
    else {
        $null
    }
    
    $graphNode = [DependencyGraphNode]::new(
        $ModuleName,
        $ModuleVersion,
        [System.Collections.ArrayList]@(),
        $notFound,
        $null,
        $moduleVersionPath
    )
    $Graph[$moduleKey] = $graphNode
    Merge-DependencyConstraint -Node $graphNode -Constraint $Constraint
    
    if ($notFound) {
        return $moduleKey
    }
    
    $deps = $installedModule.Dependencies
    if (-not $deps -or $deps.Count -eq 0) {
        Write-Verbose "${indent}No dependencies for $ModuleName"
        return $moduleKey
    }
    
    Write-Verbose "${indent}Found $($deps.Count) dependency(ies)"
    $effectiveRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $ModuleName -Version $ModuleVersion
    
    foreach ($dep in $deps) {
        $depName = $dep.Name
        $depVersion = $dep.VersionRange
        
        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
            -RedirectMap $effectiveRedirectMap -Indent $indent -DependencyVersionIsRange
        
        $resolvedDepVersion = $redirectResult.ResolvedVersion
        $resolvedDepName = $redirectResult.ResolvedName
        
        $depKey = Build-InstalledDependencyGraph -ModuleName $resolvedDepName -ModuleVersion $resolvedDepVersion `
            -Graph $Graph -RedirectMap $effectiveRedirectMap -Depth ($Depth + 1) -Constraint $redirectResult.Constraint
        Write-Verbose "${indent}  Dependency: $depKey"
        
        if (-not $graphNode.Dependencies.Contains($depKey)) {
            [void]$graphNode.Dependencies.Add($depKey)
        }
    }

    return $moduleKey
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
        [switch]$Prerelease,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
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
    
    $root = Resolve-ExactDependency -Name $Name -RequiredVersion $RequiredVersion -RedirectMap $redirectMap
    $rootKey = Build-RemoteDependencyGraph -ModuleName $root.ResolvedName -ModuleVersion $root.ResolvedVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential `
        -Prerelease:$Prerelease -Constraint $root.Constraint
    
    $redirectedKeys = Resolve-DiamondDependencies -Graph $dependencyGraph
    $rootKey = @(Resolve-GraphRootKey -RootKeys @($rootKey) -RedirectedKeys $redirectedKeys)[0]
    
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph -RootKeys @($rootKey))
    
    Write-Verbose "Install order ($($topologicalOrder.Count) modules):"
    for ($i = 0; $i -lt $topologicalOrder.Count; $i++) {
        Write-Verbose "  $($i + 1). $($topologicalOrder[$i])"
    }
    
    # Install modules in topological order
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        $modName = $node.Name
        $modVersion = $node.Version
        
        $installed = $null
        if (-not $Force) {
            $installed = Get-PSResource -Name $modName -ErrorAction SilentlyContinue | 
                Where-Object {
                    if (-not $_) { return $false }
                    $installedVersion = $_.Version.ToString()
                    if ($_.Prerelease) {
                        $installedVersion = "$installedVersion-$($_.Prerelease)"
                    }
                    $installedVersion -eq $modVersion
                }
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
            if ($Force) {
                $installParams['Reinstall'] = $true
            }
            
            Install-PSResource @installParams
        }
        else {
            Write-Verbose "Already installed: $modName version $modVersion"
        }
    }
    
    $mainNode = $dependencyGraph[$rootKey]
    Write-Host "Successfully installed $Name version $($mainNode.Version)"
}

function Save-PSResourcePinned {
    <#
    .SYNOPSIS
        Downloads a module and its dependencies with pinned versions.
        Saves as expanded module folders by default; pass -AsNupkg to save as NuGet packages.
        
    .EXAMPLE
        Save-PSResourcePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0" -Path "./packages"

    .EXAMPLE
        Save-PSResourcePinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0" -Path "./packages" -AsNupkg
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
        [switch]$AsNupkg,
        
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
    
    $root = Resolve-ExactDependency -Name $Name -RequiredVersion $RequiredVersion -RedirectMap $redirectMap
    $rootKey = Build-RemoteDependencyGraph -ModuleName $root.ResolvedName -ModuleVersion $root.ResolvedVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential `
        -Prerelease:$Prerelease -Constraint $root.Constraint
    
    $redirectedKeys = Resolve-DiamondDependencies -Graph $dependencyGraph
    $rootKey = @(Resolve-GraphRootKey -RootKeys @($rootKey) -RedirectedKeys $redirectedKeys)[0]
    
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph -RootKeys @($rootKey))
    
    Write-Verbose "Save order ($($topologicalOrder.Count) modules):"
    for ($i = 0; $i -lt $topologicalOrder.Count; $i++) {
        Write-Verbose "  $($i + 1). $($topologicalOrder[$i])"
    }
    
    # Save modules in topological order
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        $modName = $node.Name
        $modVersion = $node.Version
        
        # Existing-output detection depends on output format:
        #   -AsNupkg     -> $Path/$modName.$modVersion.nupkg
        #   (default)    -> $Path/$modName/$modVersion (expanded module folder)
        if ($AsNupkg) {
            $expectedPath = Join-Path $resolvedPath.Path "$modName.$modVersion.nupkg"
        }
        else {
            $expectedPath = Join-Path $resolvedPath.Path $modName $modVersion
        }
        
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
    
    $mainNode = $dependencyGraph[$rootKey]
    Write-Host "Successfully saved $Name version $($mainNode.Version) and dependencies to $resolvedPath"
}

<#
.SYNOPSIS
    Extracts RequiredModules and ModuleList from a manifest, deduped (RequiredModules wins).
    NuGet feeds package both as dependencies; reading both keeps the local graph consistent
    with remote graphs and prevents "assembly already loaded" errors during pre-loading.

.OUTPUTS
    Array of @{ Name; Version; IsVersionRange } hashtables.
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
            $isVersionRange = $false
            if ($Entry.ContainsKey('RequiredVersion')) {
                $version = $Entry.RequiredVersion.ToString()
            }
            elseif ($Entry.ContainsKey('ModuleVersion')) {
                $version = "[$($Entry.ModuleVersion), )"
                $isVersionRange = $true
            }
            if (-not $version) {
                throw "$Source entry '$name' has no version. All entries must specify a version (RequiredVersion or ModuleVersion)."
            }
            return @{ Name = $name; Version = $version; IsVersionRange = $isVersionRange }
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
    $rootKeys = [System.Collections.ArrayList]@()
    
    foreach ($depEntry in $moduleDependencies) {
        $moduleName = $depEntry.Name
        $moduleVersion = $depEntry.Version
        
        $mergedRedirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $moduleName -Version ($moduleVersion ?? "")
        $redirectResult = Find-DependencyRedirect -DependencyName $moduleName -DependencyVersion $moduleVersion `
            -RedirectMap $mergedRedirectMap -Indent "" -DependencyVersionIsRange:$depEntry.IsVersionRange
        
        $rootKey = Build-RemoteDependencyGraph -ModuleName $redirectResult.ResolvedName -ModuleVersion $redirectResult.ResolvedVersion `
            -Graph $dependencyGraph -RedirectMap $mergedRedirectMap -Repository $Repository -Credential $Credential `
            -Prerelease:$Prerelease -Constraint $redirectResult.Constraint
        [void]$rootKeys.Add($rootKey)
    }
    
    $redirectedKeys = Resolve-DiamondDependencies -Graph $dependencyGraph
    $resolvedRootKeys = @(Resolve-GraphRootKey -RootKeys $rootKeys.ToArray() -RedirectedKeys $redirectedKeys)
    $rootKeys = [System.Collections.ArrayList]@($resolvedRootKeys)
    
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph -RootKeys $rootKeys.ToArray())
    
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
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
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
        $installed = $null
        if (-not $Force) {
            $installed = Get-PSResource -Name $dependency.Name -ErrorAction SilentlyContinue | 
                Where-Object { $_.Version.ToString() -eq $dependency.Version }
        }
        
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
            if ($Force) {
                $installParams['Reinstall'] = $true
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
    $rootKeys = [System.Collections.ArrayList]@()
    
    foreach ($depEntry in $moduleDependencies) {
        $moduleName = $depEntry.Name
        $moduleVersion = $depEntry.Version
        
        $mergedRedirectMap = Get-MergedRedirectMap -OuterMap $redirectMap -Name $moduleName -Version ($moduleVersion ?? "")
        $redirectResult = Find-DependencyRedirect -DependencyName $moduleName -DependencyVersion $moduleVersion `
            -RedirectMap $mergedRedirectMap -Indent "" -DependencyVersionIsRange:$depEntry.IsVersionRange
        
        $rootKey = Build-InstalledDependencyGraph -ModuleName $redirectResult.ResolvedName -ModuleVersion $redirectResult.ResolvedVersion `
            -Graph $dependencyGraph -RedirectMap $mergedRedirectMap -Constraint $redirectResult.Constraint
        [void]$rootKeys.Add($rootKey)
    }
    
    $redirectedKeys = Resolve-DiamondDependencies -Graph $dependencyGraph
    $resolvedRootKeys = @(Resolve-GraphRootKey -RootKeys $rootKeys.ToArray() -RedirectedKeys $redirectedKeys)
    $rootKeys = [System.Collections.ArrayList]@($resolvedRootKeys)
    
    # Compute topological order
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph -RootKeys $rootKeys.ToArray())
    
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
        $isPrerelease = $modVersion -match '-'
        
        $loadedModule = Get-Module -Name $modName | Where-Object {
            if ($isPrerelease) {
                $_.ModuleBase -eq $node.InstalledLocation
            }
            else {
                $_.Version.ToString() -eq $modVersion
            }
        }
        
        if ($loadedModule -and -not $Force) {
            Write-Verbose "Already loaded: $modName version $modVersion"
            $importedModules[$moduleKey] = $loadedModule
            continue
        }
        
        # -Global ensures modules persist after this function returns
        $importParams = @{
            Name = if ($isPrerelease) { $node.InstalledLocation } else { $modName }
            ErrorAction = 'Stop'
            DisableNameChecking = $true
            Global = $true
        }
        if (-not $isPrerelease) {
            $importParams['RequiredVersion'] = $modVersion
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
    
    # Resolve the full dependency list (pinned versions, topological order)
    $findParams = @{
        Name = $Name
        RequiredVersion = $RequiredVersion
    }
    if ($RedirectMapPath) {
        $findParams['RedirectMapPath'] = $RedirectMapPath
    }
    
    $resolvedModules = @(Get-PSResourcesPinned @findParams)
    
    Write-Verbose "Import order ($($resolvedModules.Count) modules):"
    for ($i = 0; $i -lt $resolvedModules.Count; $i++) {
        $node = $resolvedModules[$i]
        Write-Verbose "  $($i + 1). $($node.Name)@$($node.Version)"
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
    
    Write-Verbose "Pre-loading all modules in topological order"
    
    $importedModules = @{}
    
    foreach ($node in $resolvedModules) {
        $modName = $node.Name
        $modVersion = $node.Version
        $moduleKey = "${modName}@${modVersion}"
        $isPrerelease = $modVersion -match '-'
        
        $loadedModule = Get-Module -Name $modName | Where-Object {
            if ($isPrerelease) {
                $_.ModuleBase -eq $node.InstalledLocation
            }
            else {
                $_.Version.ToString() -eq $modVersion
            }
        }
        
        if ($loadedModule -and -not $Force) {
            Write-Verbose "Already loaded: $modName version $modVersion"
            $importedModules[$moduleKey] = $loadedModule
            continue
        }
        
        # -Global ensures modules persist after this function returns
        $importParams = @{
            Name = if ($isPrerelease) { $node.InstalledLocation } else { $modName }
            ErrorAction = 'Stop'
            DisableNameChecking = $true
            Global = $true
        }
        if (-not $isPrerelease) {
            $importParams['RequiredVersion'] = $modVersion
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
    
    $mainNode = $resolvedModules |
        Where-Object { $_.Name -eq $Name } |
        Select-Object -Last 1
    $mainModuleKey = "${Name}@$($mainNode.Version)"
    $mainModule = $importedModules[$mainModuleKey]
    
    if (-not $mainModule) {
        $mainModule = Get-Module -Name $Name | Where-Object {
            $_.Version.ToString() -eq $mainNode.Version
        }
    }
    
    Write-Verbose "Successfully imported $Name version $($mainNode.Version) (and $($importedModules.Count - 1) dependencies)"
    
    if ($PassThru) {
        return $mainModule
    }
}

function Get-PSResourcesPinned {
    <#
    .SYNOPSIS
        Resolves an installed module and all of its installed dependencies with pinned versions.
        Returns results in topological order (dependencies first).
        Installed-module counterpart to Find-PSResourcesPinned.
        
    .EXAMPLE
        Get-PSResourcesPinned -Name "VMware.PowerCLI" -RequiredVersion "13.3.0"
        
    .OUTPUTS
        Array of objects with Name, Version, InstalledLocation, and Dependencies properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectMapPath
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
    
    $root = Resolve-ExactDependency -Name $Name -RequiredVersion $RequiredVersion -RedirectMap $redirectMap
    $rootKey = Build-InstalledDependencyGraph -ModuleName $root.ResolvedName -ModuleVersion $root.ResolvedVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Constraint $root.Constraint
    
    $redirectedKeys = Resolve-DiamondDependencies -Graph $dependencyGraph
    $rootKey = @(Resolve-GraphRootKey -RootKeys @($rootKey) -RedirectedKeys $redirectedKeys)[0]
    
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph -RootKeys @($rootKey))
    
    $resolvedModules = [System.Collections.ArrayList]@()
    
    foreach ($moduleKey in $topologicalOrder) {
        $node = $dependencyGraph[$moduleKey]
        
        [void]$resolvedModules.Add([PSCustomObject]@{
            Name = $node.Name
            Version = $node.Version
            InstalledLocation = $node.InstalledLocation
            Dependencies = $node.Dependencies
        })
    }
    
    Write-Verbose "Found $($resolvedModules.Count) module(s) (including main module and all dependencies)"
    
    return $resolvedModules.ToArray()
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
    
    $root = Resolve-ExactDependency -Name $Name -RequiredVersion $RequiredVersion -RedirectMap $redirectMap
    $rootKey = Build-RemoteDependencyGraph -ModuleName $root.ResolvedName -ModuleVersion $root.ResolvedVersion `
        -Graph $dependencyGraph -RedirectMap $redirectMap -Repository $Repository -Credential $Credential `
        -Prerelease:$Prerelease -Constraint $root.Constraint
    
    $redirectedKeys = Resolve-DiamondDependencies -Graph $dependencyGraph
    $rootKey = @(Resolve-GraphRootKey -RootKeys @($rootKey) -RedirectedKeys $redirectedKeys)[0]
    
    Write-Verbose "Computing topological order"
    $topologicalOrder = @(Get-TopologicalOrder -Graph $dependencyGraph -RootKeys @($rootKey))
    
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