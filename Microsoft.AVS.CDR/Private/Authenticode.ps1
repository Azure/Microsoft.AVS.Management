<#PSScriptInfo
    .VERSION 1.0

    .GUID 1a1d5e1b-0c09-4c22-b69e-3a4f4aa1c9a9

    .AUTHOR Microsoft

    .COMPANYNAME Microsoft

    .COPYRIGHT (c) Microsoft. All rights reserved.

    .DESCRIPTION Private Authenticode verification helpers for Microsoft.AVS.CDR.
#>

$script:CdrAuthenticodeSupportedExtensions = @(
    '.ps1'
    '.psd1'
    '.psm1'
    '.psc1'
    '.ps1xml'
    '.dll'
    '.exe'
)

function Assert-CdrFileSignature {
    <#
    .SYNOPSIS
        Verifies that a single file has at least one trusted Authenticode signature.

    .PARAMETER LiteralPath
        Literal path to the file to verify.

    .PARAMETER ModuleName
        Name of the module that owns the file.

    .PARAMETER ModuleVersion
        Version of the module that owns the file.

    .PARAMETER Athenticode
        Check (default) requires a trusted signature; Audit warns on signature failures.
        None skips evaluation. Operational failures terminate in both evaluating modes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$ModuleVersion,

        [ValidateSet('None', 'Check', 'Audit')]
        [CdrAuthenticodeMode]$Athenticode = [CdrAuthenticodeMode]::Check
    )

    if ($Athenticode -eq [CdrAuthenticodeMode]::None) {
        return
    }

    try {
        $signatures = @(OpenAuthenticode\Get-OpenAuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction Stop)
    }
    catch {
        $message = "Failed to verify Authenticode signature for module '$ModuleName' version '$ModuleVersion' at '$LiteralPath': $($_.Exception.Message)"
        # OpenAuthenticode reports unsigned files as ObjectNotFound, just like missing paths.
        $signatureFailure = $_.FullyQualifiedErrorId -eq 'NoSignature,OpenAuthenticode.Module.GetOpenAuthenticodeSignature'
        $cause = $_.Exception
        while ($null -ne $cause) {
            if ($cause -is [System.Security.Cryptography.CryptographicException] -or
                $cause -is [System.FormatException] -or
                ($cause -is [System.ArgumentException] -and
                    $_.FullyQualifiedErrorId -eq 'GetSignatureError,OpenAuthenticode.Module.GetOpenAuthenticodeSignature')) {
                $signatureFailure = $true
                break
            }
            $cause = $cause.InnerException
        }
        if ($Athenticode -eq [CdrAuthenticodeMode]::Audit -and $signatureFailure) {
            Write-Warning $message
            return
        }
        $exception = [System.InvalidOperationException]::new($message, $_.Exception)
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'CdrAuthenticodeBackendFailure',
            [System.Management.Automation.ErrorCategory]::SecurityError,
            $LiteralPath)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    if ($signatures.Count -eq 0) {
        $message = "No Authenticode signature was returned for module '$ModuleName' version '$ModuleVersion' at '$LiteralPath'."
        if ($Athenticode -eq [CdrAuthenticodeMode]::Audit) {
            Write-Warning $message
            return
        }
        $exception = [System.InvalidOperationException]::new($message)
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'CdrAuthenticodeSignatureMissing',
            [System.Management.Automation.ErrorCategory]::SecurityError,
            $LiteralPath)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
}

function Assert-CdrModuleSignature {
    <#
    .SYNOPSIS
        Verifies every supported file in a module directory.

    .PARAMETER ModuleDirectory
        Installed module version directory to verify.

    .PARAMETER ModuleName
        Name of the module being verified.

    .PARAMETER ModuleVersion
        Version of the module being verified.

    .PARAMETER Athenticode
        Check (default) requires trusted signatures; Audit warns and scans remaining files.
        None skips evaluation. Invalid or unreadable module trees always terminate evaluation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleDirectory,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$ModuleVersion,

        [ValidateSet('None', 'Check', 'Audit')]
        [CdrAuthenticodeMode]$Athenticode = [CdrAuthenticodeMode]::Check
    )

    if ($Athenticode -eq [CdrAuthenticodeMode]::None) {
        return
    }

    try {
        $moduleRoot = Get-Item -LiteralPath $ModuleDirectory -ErrorAction Stop
    }
    catch {
        throw "Failed to access module '$ModuleName' version '$ModuleVersion' directory '$ModuleDirectory': $($_.Exception.Message)"
    }

    if (-not $moduleRoot.PSIsContainer) {
        throw "Module '$ModuleName' version '$ModuleVersion' path '$ModuleDirectory' is not a directory."
    }

    if (($moduleRoot.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Module '$ModuleName' version '$ModuleVersion' path '$ModuleDirectory' contains a symlink or reparse point at the root."
    }

    $manifestPath = Join-Path -Path $ModuleDirectory -ChildPath "$ModuleName.psd1"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Module '$ModuleName' version '$ModuleVersion' is missing required manifest '$manifestPath'."
    }

    $pendingDirectories = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
    $pendingDirectories.Enqueue([System.IO.DirectoryInfo]$moduleRoot)

    $supportedFiles = [System.Collections.Generic.List[string]]::new()
    $totalFiles = 0

    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Dequeue()

        try {
            $children = @(Get-ChildItem -LiteralPath $currentDirectory.FullName -Force -ErrorAction Stop)
        }
        catch {
            throw "Failed to enumerate module '$ModuleName' version '$ModuleVersion' directory '$($currentDirectory.FullName)': $($_.Exception.Message)"
        }

        foreach ($child in $children) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Module '$ModuleName' version '$ModuleVersion' path '$($child.FullName)' is a symlink or reparse point, which is not allowed during signature evaluation."
            }

            if ($child.PSIsContainer) {
                $pendingDirectories.Enqueue([System.IO.DirectoryInfo]$child)
                continue
            }

            $totalFiles++
            $extension = [System.IO.Path]::GetExtension($child.Name)
            if ($extension -and ($script:CdrAuthenticodeSupportedExtensions -contains $extension.ToLowerInvariant())) {
                $supportedFiles.Add($child.FullName)
            }
        }
    }

    $filesToVerify = @($supportedFiles | Sort-Object)
    foreach ($filePath in $filesToVerify) {
        Assert-CdrFileSignature -LiteralPath $filePath -ModuleName $ModuleName -ModuleVersion $ModuleVersion -Athenticode $Athenticode
    }

    $unsupportedCount = $totalFiles - $filesToVerify.Count
    Write-Verbose "Evaluated $($filesToVerify.Count) supported file(s) in $Athenticode mode for module '$ModuleName' version '$ModuleVersion' under '$ModuleDirectory'; ignored $unsupportedCount unsupported file(s)."
}

function Assert-CdrResolvedModuleSignatureGraph {
    <#
    .SYNOPSIS
        Verifies every resolved module directory in a dependency graph.

    .PARAMETER Modules
        Module graph nodes with Name, Version, and InstalledLocation properties.

    .PARAMETER Athenticode
        Check (default) fails closed; Audit warns and continues signature evaluation across the graph.
        None skips evaluation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Modules,

        [ValidateSet('None', 'Check', 'Audit')]
        [CdrAuthenticodeMode]$Athenticode = [CdrAuthenticodeMode]::Check
    )

    foreach ($module in $Modules) {
        Assert-CdrModuleSignature -ModuleDirectory $module.InstalledLocation `
            -ModuleName $module.Name -ModuleVersion $module.Version -Athenticode $Athenticode
    }
}

Set-Alias -Name Assert-CdrResolvedModuleSignatures -Value Assert-CdrResolvedModuleSignatureGraph -Scope Script
