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
        
    .PARAMETER Version
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
        Install-PSResourcePinned -Name "VMware.PowerCLI" -Version "13.3.0"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Version,
        
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
    
    # Default redirect map - keyed on dependency name@version or name only
    # falls back to name-only for missing versions
    $defaultRedirectMap = @{
    }
    
    # Load redirect map from file or use default
    if ($RedirectMapPath -and (Test-Path $RedirectMapPath)) {
        Write-Verbose "Loading redirect map from: $RedirectMapPath"
        $redirectMap = Get-Content $RedirectMapPath -Raw | ConvertFrom-Json -AsHashtable
    }
    else {
        Write-Verbose "Using default redirect map"
        $redirectMap = $defaultRedirectMap
    }
    
    # Get module metadata
    Write-Verbose "Searching for module: $Name version $Version"
    $findParams = @{
        Name = $Name
    }
    if ($Version) {
        $findParams['Version'] = $Version
    }
    if ($Repository) {
        $findParams['Repository'] = $Repository
    }
    if ($Credential) {
        $findParams['Credential'] = $Credential
    }
    
    $moduleInfo = Find-PSResource @findParams | Select-Object -First 1
    if (-not $moduleInfo) {
        throw "Module '$Name' $(if($Version){"version $Version"}) not found"
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
            
            # Apply redirect if exists - check name@version first, then name-only fallback
            $depKey = "${depName}@${depVersion}"
            $nameOnlyKey = $depName
            
            if ($RedirectMap.ContainsKey($depKey)) {
                $originalVersion = $depVersion
                $depVersion = $RedirectMap[$depKey]
                Write-Verbose "${indent}Redirecting dependency: $depName $originalVersion -> $depVersion (from redirect map)"
            }
            elseif ($RedirectMap.ContainsKey($nameOnlyKey)) {
                $originalVersion = $depVersion
                $depVersion = $RedirectMap[$nameOnlyKey]
                Write-Verbose "${indent}Redirecting dependency: $depName $originalVersion -> $depVersion (from name-only redirect)"
            }
            else {
                Write-Verbose "${indent}Processing dependency: $depName version $depVersion"
            }
            
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
                # Recursively install nested dependencies
                Install-DependenciesRecursive -ModuleInfo $depModuleInfo -RedirectMap $RedirectMap `
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
        
    .PARAMETER Version
        The exact version of the module to import.
        
    .PARAMETER Force
        Force reimport of the module even if already loaded.
        
    .PARAMETER Prefix
        Prefix to add to the nouns of imported commands.
        
    .PARAMETER PassThru
        Returns the module info object after import.
        
    .PARAMETER Global
        Import the module into the global session state.
        
    .EXAMPLE
        Import-ModulePinned -Name "VMware.PowerCLI" -Version "13.3.0"
        
    .EXAMPLE
        Import-ModulePinned -Name "Microsoft.AVS.Management" -Version "1.0.0" -Force -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Version,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [string]$Prefix,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [switch]$Global
    )
    
    # Track imported modules to avoid circular dependencies
    $script:importedModules = @{}
    
    # Recursive function to import dependencies
    function Import-DependenciesRecursive {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ModuleName,
            
            [Parameter(Mandatory = $false)]
            [string]$ModuleVersion,
            
            [Parameter(Mandatory = $true)]
            [hashtable]$ImportedModules,
            
            [Parameter(Mandatory = $false)]
            [switch]$ForceReimport,
            
            [Parameter(Mandatory = $false)]
            [switch]$GlobalScope,
            
            [Parameter(Mandatory = $false)]
            [int]$Depth = 0
        )
        
        $indent = "  " * $Depth
        
        # Check if already imported
        $moduleKey = if ($ModuleVersion) { "${ModuleName}@${ModuleVersion}" } else { $ModuleName }
        if ($ImportedModules.ContainsKey($moduleKey) -and -not $ForceReimport) {
            Write-Verbose "${indent}Module already imported: $ModuleName $(if($ModuleVersion){"version $ModuleVersion"})"
            return
        }
        
        # Find the installed module
        $findParams = @{
            Name = $ModuleName
        }
        if ($ModuleVersion) {
            $findParams['Version'] = $ModuleVersion
        }
        
        $installedModule = Get-PSResource @findParams -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if (-not $installedModule) {
            Write-Error "${indent}Module not found: $ModuleName $(if($ModuleVersion){"version $ModuleVersion"})"
            throw "Please install the module first using Install-PSResourcePinned"
        }
        
        $actualVersion = $installedModule.Version.ToString()
        Write-Verbose "${indent}Processing module: $ModuleName version $actualVersion"
        
        # Load the module manifest to get dependencies
        $manifestPath = Join-Path $installedModule.InstalledLocation "$ModuleName.psd1"
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
                        
                        Write-Verbose "${indent}Required dependency: $depName $(if($depVersion){"version $depVersion"})"
                        
                        # Recursively import the dependency
                        Import-DependenciesRecursive -ModuleName $depName -ModuleVersion $depVersion `
                            -ImportedModules $ImportedModules -ForceReimport:$ForceReimport `
                            -GlobalScope:$GlobalScope -Depth ($Depth + 1)
                    }
                }
            }
            catch {
                throw "Could not parse manifest for $($ModuleName): $_"
            }
        }
        
        # Import the module
        try {
            $importParams = @{
                Name = $ModuleName
                ErrorAction = 'Stop'
            }
            
            if ($ModuleVersion) {
                $importParams['RequiredVersion'] = $ModuleVersion
            }
            
            if ($ForceReimport) {
                $importParams['Force'] = $true
            }
            
            if ($GlobalScope) {
                $importParams['Global'] = $true
            }
            
            Write-Verbose "${indent}Importing: $ModuleName version $actualVersion"
            Import-Module @importParams
            
            # Mark as imported
            $ImportedModules[$moduleKey] = $true
        }
        catch {
            throw "Failed to import $($ModuleName): $_"
        }
    }
    
    Write-Verbose "Importing module: $Name version $Version"
    
    # Import dependencies recursively
    $importDepParams = @{
        ModuleName = $Name
        ModuleVersion = $Version
        ImportedModules = $script:importedModules
        ForceReimport = $Force
        GlobalScope = $Global
    }
    
    Import-DependenciesRecursive @importDepParams
    
    # Import the main module with user-specified options
    $finalImportParams = @{
        Name = $Name
        RequiredVersion = $Version
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
    
    Write-Verbose "Successfully imported $Name version $Version"
    
    if ($PassThru) {
        return $result
    }
}