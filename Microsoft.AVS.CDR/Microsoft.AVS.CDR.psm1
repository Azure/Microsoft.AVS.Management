$ErrorActionPreference = 'Stop'

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
        Write-Verbose "${Indent}Processing dependency: $DependencyName version $DependencyVersion"
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
        if ($Version -match '[\[\(]([0-9\.]+)') {
            # Extract the first version number from a version range
            $baseVersion = $matches[1]
        }
        
        $parsedVersion = [version]$baseVersion
        $versionPatterns = @(
            $baseVersion,  # Full version (e.g., 1.4.0.15939652)
            "$($parsedVersion.Major).$($parsedVersion.Minor)",  # Major.Minor (e.g., 1.4)
            "$($parsedVersion.Major)"  # Major only (e.g., 1)
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
        [PSCredential]$Credential
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
    
    # Get module metadata
    Write-Verbose "Searching for module: $Name version $RequiredVersion"
    $findParams = @{
        Name = $Name
    }
    if ($RequiredVersion) {
        $findParams['Version'] = $RequiredVersion
    }
    if ($Repository) {
        $findParams['Repository'] = $Repository
    }
    if ($Credential) {
        $findParams['Credential'] = $Credential
    }
    
    $moduleInfo = Find-PSResource @findParams | Select-Object -First 1
    if (-not $moduleInfo) {
        throw "Module '$Name' $(if($RequiredVersion){"version $RequiredVersion"}) not found"
    }
    
    $requestedVersion = $moduleInfo.Version.ToString()
    Write-Verbose "Installing $Name version $requestedVersion"
    
    # Track processed modules to avoid circular dependencies
    $processedModules = @{}
    
    # Recursive function to install dependencies
    function Install-DependenciesRecursive {
        param(
            [Parameter(Mandatory = $true)]
            $ModuleInfo,
            [Parameter(Mandatory = $true)]
            [hashtable]$RedirectMap,
            [Parameter(Mandatory = $true)]
            [hashtable]$ProcessedModules,
            [Parameter(Mandatory = $true)]
            [string]$Scope,
            [Parameter(Mandatory = $false)]
            [string]$Repository,
            [Parameter(Mandatory = $false)]
            [PSCredential]$Credential,
            [Parameter(Mandatory = $false)]
            [int]$Depth = 0
        )
        
        $indent = "  " * $Depth
        
        if (-not $ModuleInfo.Dependencies) {
            return
        }
        
        foreach ($dep in $ModuleInfo.Dependencies) {
            $depName = $dep.Name
            $depVersion = $dep.VersionRange
            
            # Find and apply redirect (handles all version parsing and resolution)
            $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
                -RedirectMap $RedirectMap -Indent $indent
            
            $depVersion = $redirectResult.ResolvedVersion
            $depName = $redirectResult.ResolvedName
            
            # Check if already processed
            $moduleKey = "${depName}@${depVersion}"
            if ($ProcessedModules.ContainsKey($moduleKey)) {
                Write-Verbose "${indent}Dependency already processed: $depName version $depVersion"
                continue
            }
            
            # Mark as processed
            $ProcessedModules[$moduleKey] = $true
            
            # Get dependency metadata to check for nested dependencies
            $findDepParams = @{
                Name = $depName
                Version = $depVersion
            }
            if ($Repository) {
                $findDepParams['Repository'] = $Repository
            }
            if ($Credential) {
                $findDepParams['Credential'] = $Credential
            }
            
            $depModuleInfo = Find-PSResource @findDepParams -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($depModuleInfo) {
                # Merge redirect map with dependency-specific map
                $depRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $depName -Version $depVersion
                
                # Recursively install nested dependencies
                Install-DependenciesRecursive -ModuleInfo $depModuleInfo -RedirectMap $depRedirectMap `
                    -ProcessedModules $ProcessedModules -Scope $Scope -Repository $Repository `
                    -Credential $Credential -Depth ($Depth + 1)
            }
            
            # Check if already installed with exact version
            $installed = Get-PSResource -Name $depName -ErrorAction SilentlyContinue | 
                Where-Object { $_.Version.ToString() -eq $depVersion }
            
            if (-not $installed) {
                $installParams = @{
                    Name = $depName
                    Version = $depVersion
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
                Write-Verbose "${indent}Dependency already installed: $depName version $depVersion"
            }
        }
    }
    
    # Install all dependencies recursively
    $installDepParams = @{
        ModuleInfo = $moduleInfo
        RedirectMap = $redirectMap
        ProcessedModules = $processedModules
        Scope = $Scope
    }
    if ($Repository) {
        $installDepParams['Repository'] = $Repository
    }
    if ($Credential) {
        $installDepParams['Credential'] = $Credential
    }
    
    Install-DependenciesRecursive @installDepParams
    
    # Install the main module without resolving dependencies (already handled)
    $mainInstallParams = @{
        Name = $Name
        Version = $requestedVersion
        Scope = $Scope
        TrustRepository = $true
        SkipDependencyCheck = $true
    }
    if ($Repository) {
        $mainInstallParams['Repository'] = $Repository
    }
    if ($Credential) {
        $mainInstallParams['Credential'] = $Credential
    }
    
    Install-PSResource @mainInstallParams
    Write-Host "Successfully installed $Name version $requestedVersion"
}

function Import-ModulePinned {
    <#
    .SYNOPSIS
        Imports a PowerShell module with explicit, recursive dependency loading at required versions.
    
    .DESCRIPTION
        This function imports a module and explicitly loads all its dependencies recursively,
        ensuring each dependency is loaded at the exact version specified in the manifest.
        This provides deterministic module loading and prevents version conflicts.
        
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
        
    .PARAMETER Global
        Import the module into the global session state.
        
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
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [switch]$Global
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
    
    # Track imported modules to avoid circular dependencies
    $script:importedModules = @{}
    
    # Recursive function to import dependencies
    function Import-DependenciesRecursive {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name,
            
            [Parameter(Mandatory = $false)]
            [string]$Version,
            
            [Parameter(Mandatory = $true)]
            [hashtable]$ImportedModules,
            
            [Parameter(Mandatory = $true)]
            [hashtable]$RedirectMap,
            
            [Parameter(Mandatory = $false)]
            [switch]$ForceReimport,
            
            [Parameter(Mandatory = $false)]
            [switch]$GlobalScope,
            
            [Parameter(Mandatory = $false)]
            [int]$Depth = 0
        )
        
        $indent = "  " * $Depth
        
        # Check if already imported
        $moduleKey = if ($Version) { "${Name}@${Version}" } else { $Name }
        if ($ImportedModules.ContainsKey($moduleKey) -and -not $ForceReimport) {
            Write-Verbose "${indent}Module already imported: $Name $(if($Version){"version $Version"})"
            return
        }
        
        # Find the installed module
        $findParams = @{
            Name = $Name
        }
        if ($Version) {
            $findParams['Version'] = $Version
        }
        
        $installedModule = Get-PSResource @findParams -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if (-not $installedModule) {
            Write-Error "${indent}Module not found: $Name $(if($Version){"version $Version"})"
            throw "Please install the module first using Install-PSResourcePinned"
        }
        
        $actualVersion = $installedModule.Version.ToString()
        Write-Verbose "${indent}Processing module: $Name version $actualVersion"
        
        # Load the module manifest to get dependencies
        $manifestPath = Join-Path $installedModule.InstalledLocation "$Name.psd1"
        if (Test-Path $manifestPath) {
            try {
                $manifest = Import-PowerShellDataFile -Path $manifestPath
                
                # Process RequiredModules
                if ($manifest.RequiredModules) {
                    Write-Verbose "${indent}Found $($manifest.RequiredModules.Count) required module(s)"
                    
                    foreach ($reqModule in $manifest.RequiredModules) {
                        $depName = if ($reqModule -is [string]) { $reqModule } else { $reqModule.ModuleName }
                        $depVersion = if ($reqModule -is [hashtable]) { 
                            if ($reqModule.RequiredVersion) { 
                                $reqModule.RequiredVersion 
                            } 
                            elseif ($reqModule.ModuleVersion) { 
                                $reqModule.ModuleVersion 
                            }
                        }
                        
                        # Find and apply redirect (handles all version parsing and resolution)
                        $redirectResult = Find-DependencyRedirect -DependencyName $depName -DependencyVersion $depVersion `
                            -RedirectMap $RedirectMap -Indent $indent
                        
                        $depVersion = $redirectResult.ResolvedVersion
                        $depName = $redirectResult.ResolvedName
                        
                        Write-Verbose "${indent}Required dependency: $depName $(if($depVersion){"version $depVersion"})"
                        
                        # Merge redirect map with dependency-specific map
                        $depRedirectMap = Get-MergedRedirectMap -OuterMap $RedirectMap -Name $depName -Version $depVersion
                        
                        # Recursively import the dependency
                        Import-DependenciesRecursive -Name $depName -Version $depVersion `
                            -ImportedModules $ImportedModules -RedirectMap $depRedirectMap -ForceReimport:$ForceReimport `
                            -GlobalScope:$GlobalScope -Depth ($Depth + 1)
                    }
                }
            }
            catch {
                throw "Could not parse manifest for $($Name): $_"
            }
        }
        
        # Import the module
        try {
            $importParams = @{
                Name = $Name
                ErrorAction = 'Stop'
            }
            
            if ($Version) {
                $importParams['RequiredVersion'] = $Version
            }
            
            if ($ForceReimport) {
                $importParams['Force'] = $true
            }
            
            if ($GlobalScope) {
                $importParams['Global'] = $true
            }
            
            Write-Verbose "${indent}Importing: $Name version $actualVersion"
            
            # Check if module with this exact version is already loaded
            $loadedModule = Get-Module -Name $Name | Where-Object { $_.Version.ToString() -eq $Version }
            
            if ($loadedModule -and -not $ForceReimport) {
                Write-Verbose "${indent}Module $Name version $Version already loaded in session"
                $ImportedModules[$moduleKey] = $true
            }
            else {
                Import-Module @importParams
                # Mark as imported
                $ImportedModules[$moduleKey] = $true
            }
        }
        catch {
            throw "Failed to import $($Name): $_"
        }
    }
    
    Write-Verbose "Importing module: $Name version $RequiredVersion"
    
    # Import dependencies recursively
    $importDepParams = @{
        Name = $Name
        Version = $RequiredVersion
        ImportedModules = $script:importedModules
        RedirectMap = $redirectMap
        ForceReimport = $Force
        GlobalScope = $Global
    }
    
    Import-DependenciesRecursive @importDepParams
    
    # Check if the main module is already loaded (it would be if it was a dependency)
    $loadedMainModule = Get-Module -Name $Name | Where-Object { $_.Version.ToString() -eq $RequiredVersion }
    
    if ($loadedMainModule -and -not $Force) {
        Write-Verbose "Module $Name version $RequiredVersion already loaded in session"
        if ($PassThru) {
            return $loadedMainModule
        }
        return
    }
    
    # Import the main module with user-specified options
    $finalImportParams = @{
        Name = $Name
        RequiredVersion = $RequiredVersion
        ErrorAction = 'Stop'
    }
    
    if ($Force) {
        $finalImportParams['Force'] = $true
    }
    
    if ($Prefix) {
        $finalImportParams['Prefix'] = $Prefix
    }
    
    if ($PassThru) {
        $finalImportParams['PassThru'] = $true
    }
    
    if ($Global) {
        $finalImportParams['Global'] = $true
    }
    
    $result = Import-Module @finalImportParams
    
    Write-Verbose "Successfully imported $Name version $RequiredVersion"
    
    if ($PassThru) {
        return $result
    }
}