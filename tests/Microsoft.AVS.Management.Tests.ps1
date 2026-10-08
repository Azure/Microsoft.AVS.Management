BeforeAll {
    # AVSAttribute and AVSSecureFolder are loaded from Classes.ps1 via
    # ScriptsToProcess when Import-Module runs below. Do not pre-define them
    # with the PowerShell 'class' keyword — that would prevent Add-Type from
    # running (its if (-not ...) guard) and defeat cross-SessionState visibility.

    # Define stub functions for VMware cmdlets so Pester can mock them
    # These are only created when the real cmdlets are not available (e.g. no PowerCLI installed)
    $vmwareCmdlets = @(
        'Get-Cluster', 'Get-VMHost', 'Get-Datastore', 'Get-View',
        'Copy-DatastoreItem', 'New-PSDrive', 'Remove-PSDrive'
    )
    foreach ($cmdlet in $vmwareCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$cmdlet" -Value { param() $null }
        }
    }
    # Always override Get-VMHost with a stub that accepts pipeline input,
    # preventing mock failures when PowerCLI is not installed
    function global:Get-VMHost {
        param($Name, $Location, $State,
              [Parameter(ValueFromPipeline=$true)]$InputObject)
        process { $null }
    }


    if (-not ('VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder' -as [type])) {
        Add-Type @"
namespace VMware.VimAutomation.ViCore.Types.V1.Inventory {
    public class Folder {}
}
"@
    }

    # Import the Management module
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1"
    Import-Module $modulePath -Force
}

AfterAll {
    # Clean up
    Get-Module Microsoft.AVS.Management -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe "Microsoft.AVS.Management Module" {
    Context "Module Loading" {
        It "Should import the module successfully" {
            $module = Get-Module Microsoft.AVS.Management
            $module | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Set-ToolsRepo" {
    Context "Parameter Validation" {
        It "Should require source datastore, zip path, and expected hash in upload mode" {
            { Set-ToolsRepo } |
                Should -Throw -ExpectedMessage "*SourceDatastoreName, ToolsZipPath, and ExpectedHash are required when -Validate is not specified*"
        }

        It "Should expose the supported Run Command parameter and AVSAttribute contract" {
            $command = Get-Command Set-ToolsRepo

            foreach ($parameterName in @('SourceDatastoreName', 'ToolsZipPath', 'ExpectedHash')) {
                $parameter = $command.Parameters[$parameterName]
                $parameter.ParameterType.Name | Should -Be 'String'
                ($parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory |
                    Should -BeFalse
            }

            $command.Parameters['Validate'].ParameterType.Name | Should -Be 'SwitchParameter'
            $command.Parameters.Keys | Should -Not -Contain 'ToolsURL'

            $avsAttribute = $command.ScriptBlock.Attributes | Where-Object { $_ -is [AVSAttribute] }
            $avsAttribute.Count | Should -Be 1
            $avsAttribute.Timeout.TotalMinutes | Should -Be 30
            $avsAttribute.UpdatesSDDC | Should -BeTrue
        }

        It "Should reject invalid upload input: <Case>" -TestCases @(
            @{
                Case = 'short SHA-256 hash'
                ToolsZipPath = 'AVS-ToolsRepo-Staging/tools.zip'
                ExpectedHash = 'ABC123'
                ExpectedMessage = '*exactly 64 hexadecimal characters*'
            },
            @{
                Case = 'non-hexadecimal SHA-256 hash'
                ToolsZipPath = 'AVS-ToolsRepo-Staging/tools.zip'
                ExpectedHash = ('G' * 64)
                ExpectedMessage = '*exactly 64 hexadecimal characters*'
            },
            @{
                Case = 'parent-directory traversal'
                ToolsZipPath = '../tools.zip'
                ExpectedHash = ('A' * 64)
                ExpectedMessage = '*safe relative path to a zip file*'
            },
            @{
                Case = 'absolute path'
                ToolsZipPath = 'C:/tools.zip'
                ExpectedHash = ('A' * 64)
                ExpectedMessage = '*safe relative path to a zip file*'
            },
            @{
                Case = 'non-ZIP file'
                ToolsZipPath = 'AVS-ToolsRepo-Staging/tools.tgz'
                ExpectedHash = ('A' * 64)
                ExpectedMessage = '*safe relative path to a zip file*'
            },
            @{
                Case = 'managed GuestStore folder'
                ToolsZipPath = 'GuestStore/tools.zip'
                ExpectedHash = ('A' * 64)
                ExpectedMessage = '*must not be inside the managed GuestStore folder*'
            }
        ) {
            param($ToolsZipPath, $ExpectedHash, $ExpectedMessage)

            Mock Get-Datastore { } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath $ToolsZipPath `
                    -ExpectedHash $ExpectedHash
            } | Should -Throw -ExpectedMessage $ExpectedMessage

            Should -Not -Invoke Get-Datastore -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management
        }

    }

    Context "PSDrive Cleanup" {
        It "Should clean invocation-owned resources when archive hash verification fails" {
            $expectedHash = 'A' * 64
            $script:sourceDriveCreated = $false

            Mock Get-Datastore {
                [PSCustomObject]@{
                    Name = 'vsanDatastore'
                    ExtensionData = [PSCustomObject]@{
                        Summary = [PSCustomObject]@{ Type = 'vsan' }
                    }
                }
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { [PSCustomObject]@{ FullName = $Path } } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive {
                if ($script:sourceDriveCreated) {
                    return [PSCustomObject]@{ Name = $Name }
                }

                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive {
                $script:sourceDriveCreated = $true
                [PSCustomObject]@{ Name = $Name }
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-FileHash {
                [PSCustomObject]@{ Hash = ('B' * 64) }
            } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive {
                $script:sourceDriveCreated = $false
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                    -ExpectedHash $expectedHash
            } | Should -Throw -ExpectedMessage "*SHA-256 hash mismatch*"

            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                $Name -like 'AVSToolsSrc_*'
            }
            Should -Invoke Get-PSDrive -ModuleName Microsoft.AVS.Management -Times 3 -Exactly -ParameterFilter {
                $Name -like 'AVSToolsSrc_*'
            }
            Should -Invoke Remove-Item -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -like '*avs-toolsrepo-*' -and $Recurse -and $Force
            }
            Should -Not -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Name -like 'AVSToolsDs_*'
            }
        }

        if (-not (Get-Module Microsoft.AVS.Management)) {
            Import-Module (Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1") -Force
        }

        InModuleScope 'Microsoft.AVS.Management' {
            It "Should report both source preparation and PSDrive cleanup failures" {
                $script:sourceDriveExists = $false

                Mock Get-PSDrive {
                    if ($script:sourceDriveExists) {
                        return [PSCustomObject]@{ Name = $Name }
                    }

                    return $null
                } -ModuleName Microsoft.AVS.Management
                Mock New-PSDrive {
                    $script:sourceDriveExists = $true
                } -ModuleName Microsoft.AVS.Management
                Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
                Mock Copy-DatastoreItem { throw 'Datastore copy failed' } -ModuleName Microsoft.AVS.Management
                Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

                {
                    Copy-ToolsRepoArchive `
                        -SourceDatastore ([PSCustomObject]@{ Name = 'vsanDatastore' }) `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64) `
                        -LocalToolsFile (Join-Path $TestDrive 'tools.zip') `
                        -SourceDriveName 'AVSToolsSrc_test'
                } | Should -Throw -ExpectedMessage '*Datastore copy failed*Additionally, cleanup failed*Failed to remove temporary PSDrive*'
            }
        }
    }



    Context "Validate Mode Behavior" {
        It "Should succeed when metadata files are in sync and reference latest version" {
            $script:destinationDriveCreated = $false

            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive {
                if ($script:destinationDriveCreated) {
                    return [PSCustomObject]@{ Name = $Name }
                }

                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive {
                $script:destinationDriveCreated = $true
                [PSCustomObject]@{ Name = $Name }
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive {
                $script:destinationDriveCreated = $false
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { [PSCustomObject]@{ FullName = $Path } } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Write-Host { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) {
                    return $ChildPath
                }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                @(
                    [PSCustomObject]@{ Name = "vmtools-12.1.0"; PSIsContainer = $true },
                    [PSCustomObject]@{ Name = "vmtools-12.3.0"; PSIsContainer = $true }
                )
            } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem {
                [PSCustomObject]@{ Name = 'metadata.json'; Datastore = 'vsanDatastore' }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"1.0","type":"collection","vmtools":"vmtools-12.3.0/","vmtools-12.1.0":"vmtools-12.1.0/"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"1.0","type":"leaf","installer":{"file":"VMware-tools-12.3.0-22234872-x64.exe","version":"12.3.0"}}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            $output = Set-ToolsRepo -Validate

            $output | Should -BeNullOrEmpty

            Should -Invoke Write-Host -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like "*validation result: SUCCESS*"
            }
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
            Should -Invoke New-Item -Times 1 -Exactly -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $ItemType -eq 'Directory' -and $Path -like '*avs-validate-metadata-*'
            }
            Should -Invoke Remove-Item -Times 1 -Exactly -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Path -like '*avs-validate-metadata-*' -and $Recurse -and $Force
            }
            Should -Invoke Remove-PSDrive -Times 1 -Exactly -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Name -like 'AVSToolsDs_*'
            }
        }

        It "Should report FAILURE when top-level and version metadata do not match" {
            $script:destinationDriveCreated = $false

            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive {
                if ($script:destinationDriveCreated) {
                    return [PSCustomObject]@{ Name = $Name }
                }

                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive {
                $script:destinationDriveCreated = $true
                [PSCustomObject]@{ Name = $Name }
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive {
                $script:destinationDriveCreated = $false
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { [PSCustomObject]@{ FullName = $Path } } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Write-Host { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) { return $ChildPath }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Path -like '*metadata.json' -or
                $Path -like '*GuestStore*' -or
                $Path -like '*avs-validate-metadata-*'
            }
            Mock Get-ChildItem {
                @(
                    [PSCustomObject]@{ Name = "vmtools-12.1.0"; PSIsContainer = $true },
                    [PSCustomObject]@{ Name = "vmtools-12.3.0"; PSIsContainer = $true }
                )
            } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            # Top-level and version metadata intentionally differ
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"1.0","type":"collection","vmtools":"vmtools-12.3.0/","vmtools-12.1.0":"vmtools-12.1.0/"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"1.0","type":"leaf","installer":{"file":"VMware-tools-12.2.0-21223074-x64.exe","version":"12.2.0"}}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            # When all datastores fail validation, function throws
            { Set-ToolsRepo -Validate } | Should -Throw -ExpectedMessage "*Validation failed for all datastores*"

            Should -Invoke Write-Host -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like "*validation result: FAILURE*"
            }
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
            Should -Invoke New-Item -Times 1 -Exactly -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $ItemType -eq 'Directory' -and $Path -like '*avs-validate-metadata-*'
            }
            Should -Invoke Remove-Item -Times 1 -Exactly -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Path -like '*avs-validate-metadata-*' -and $Recurse -and $Force
            }
            Should -Invoke Remove-PSDrive -Times 1 -Exactly -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Name -like 'AVSToolsDs_*'
            }
        }

        It "Should report both validation and destination PSDrive cleanup failures" {
            $script:destinationDriveExists = $false

            Mock Get-Datastore {
                @([PSCustomObject]@{
                    Name = 'vsanDatastore'
                    ExtensionData = @{ Summary = @{ Type = 'vsan' } }
                })
            } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive {
                if ($script:destinationDriveExists) {
                    return [PSCustomObject]@{ Name = $Name }
                }

                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive {
                $script:destinationDriveExists = $true
            } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $false } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Write-Error { } -ModuleName Microsoft.AVS.Management
            Mock Write-Host { } -ModuleName Microsoft.AVS.Management

            { Set-ToolsRepo -Validate } | Should -Throw -ExpectedMessage '*Validation failed for all datastores*vsanDatastore*GuestStore tools path not found*Additionally, cleanup failed*Failed to remove temporary PSDrive*'

            Should -Not -Invoke Write-Error -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Write-Host -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like '*validation result: SUCCESS*'
            }
        }

    }

    Context "Archive Extraction Validation" {
        It "Should throw when archive extraction fails" {
            $expectedHash = 'A' * 64
            $script:sourceDriveCreated = $false

            Mock Get-Datastore {
                [PSCustomObject]@{
                    Name = 'vsanDatastore'
                    ExtensionData = [PSCustomObject]@{
                        Summary = [PSCustomObject]@{ Type = 'vsan' }
                    }
                }
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { [PSCustomObject]@{ FullName = $Path } } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive {
                if ($script:sourceDriveCreated) {
                    return [PSCustomObject]@{ Name = $Name }
                }

                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive {
                $script:sourceDriveCreated = $true
                [PSCustomObject]@{ Name = $Name }
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-FileHash {
                [PSCustomObject]@{ Hash = $expectedHash }
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive {
                $script:sourceDriveCreated = $false
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem { $null } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { throw "Invalid archive" } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                    -ExpectedHash $expectedHash
            } | Should -Throw -ExpectedMessage "*Failed to extract tools archive*Invalid archive*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 0
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                $Name -like 'AVSToolsSrc_*'
            }
            Should -Invoke Remove-Item -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -like '*avs-toolsrepo-*' -and $Recurse -and $Force
            }
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Name -like 'AVSToolsDs_*'
            }
        }

        It "Should reject malformed archive structure: <Case>" -TestCases @(
            @{
                Case = 'windows64 directory is missing'
                MissingItem = 'Windows64'
                ExpectedMessage = '*windows64 directory not found*'
            },
            @{
                Case = 'top-level metadata.json is missing'
                MissingItem = 'TopLevelMetadata'
                ExpectedMessage = '*metadata.json not found in windows64 directory*'
            },
            @{
                Case = 'vmtools version folder is missing'
                MissingItem = 'VersionFolder'
                ExpectedMessage = '*No vmtools folder found inside windows64*'
            },
            @{
                Case = 'version metadata.json is missing'
                MissingItem = 'VersionMetadata'
                ExpectedMessage = '*metadata.json not found inside vmtools folder*'
            },
            @{
                Case = 'metadata.json contains invalid JSON'
                MissingItem = 'InvalidJson'
                ExpectedMessage = '*Failed to parse metadata.json in extracted archive*'
            },
            @{
                Case = 'metadata versions do not match the extracted folder'
                MissingItem = 'MetadataVersionMismatch'
                ExpectedMessage = '*Archive metadata versions must match extracted VMware Tools version*'
            }
        ) {
            param($MissingItem, $ExpectedMessage)

            $expectedHash = 'A' * 64
            $script:sourceDriveCreated = $false
            $versionFolderPath = Join-Path $TestDrive 'vmtools-12.4.0'

            Mock Get-Datastore {
                [PSCustomObject]@{
                    Name = 'vsanDatastore'
                    ExtensionData = [PSCustomObject]@{
                        Summary = [PSCustomObject]@{ Type = 'vsan' }
                    }
                }
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { [PSCustomObject]@{ FullName = $Path } } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive {
                if ($script:sourceDriveCreated) {
                    return [PSCustomObject]@{ Name = $Name }
                }

                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive {
                $script:sourceDriveCreated = $true
                [PSCustomObject]@{ Name = $Name }
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path {
                if ($MissingItem -eq 'Windows64' -and $Path -like '*vmware*apps*vmtools*windows64') {
                    return $false
                }
                if ($MissingItem -eq 'TopLevelMetadata' -and $Path -like '*windows64*metadata.json') {
                    return $false
                }
                if ($MissingItem -eq 'VersionMetadata' -and $Path -eq (Join-Path $versionFolderPath 'metadata.json')) {
                    return $false
                }

                return $true
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-FileHash { [PSCustomObject]@{ Hash = $expectedHash } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-Content {
                param($LiteralPath)

                if ($MissingItem -eq 'InvalidJson') {
                    return '{invalid-json'
                }

                if ($MissingItem -eq 'MetadataVersionMismatch' -and $LiteralPath -eq (Join-Path $versionFolderPath 'metadata.json')) {
                    return '{"version":"1.0","type":"leaf","installer":{"file":"VMware-tools-12.3.0-22234872-x64.exe","version":"12.3.0"}}'
                }

                if ($LiteralPath -eq (Join-Path $versionFolderPath 'metadata.json')) {
                    return '{"version":"1.0","type":"leaf","installer":{"file":"VMware-tools-12.4.0-23259341-x64.exe","version":"12.4.0"}}'
                }

                return '{"version":"1.0","type":"collection","vmtools":"vmtools-12.4.0/","vmtools-12.3.0":"vmtools-12.3.0/"}'
            } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                if ($MissingItem -eq 'VersionFolder') {
                    return @()
                }

                return @([PSCustomObject]@{
                    Name = 'vmtools-12.4.0'
                    FullName = $versionFolderPath
                })
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Directory }
            Mock Get-VMHost { } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive {
                $script:sourceDriveCreated = $false
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                    -ExpectedHash $expectedHash
            } | Should -Throw -ExpectedMessage $ExpectedMessage

            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                $Name -like 'AVSToolsSrc_*'
            }
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Name -like 'AVSToolsDs_*'
            }
            Should -Not -Invoke Get-VMHost -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Destination -like '*GuestStore*'
            }
        }
    }

    Context "vSAN Datastore Validation" {
        It "Should throw when no vSAN datastores found" {
            Mock Get-Datastore { @() } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-FileHash { } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                    -ExpectedHash ('A' * 64)
            } | Should -Throw -ExpectedMessage "*No vSAN datastores found*"

            Should -Invoke Get-Datastore -ModuleName Microsoft.AVS.Management -Times 1
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Get-FileHash -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when the source vSAN datastore is not found" {
            Mock Get-Datastore {
                @([PSCustomObject]@{
                    Name = 'anotherVsanDatastore'
                    ExtensionData = [PSCustomObject]@{
                        Summary = [PSCustomObject]@{ Type = 'vsan' }
                    }
                })
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                    -ExpectedHash ('A' * 64)
            } | Should -Throw -ExpectedMessage "*Source vSAN datastore 'vsanDatastore' was not found*"

            Should -Not -Invoke New-Item -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when more than one vSAN datastore matches the source name" {
            Mock Get-Datastore {
                @(
                    [PSCustomObject]@{
                        Name = 'vsanDatastore'
                        ExtensionData = [PSCustomObject]@{
                            Summary = [PSCustomObject]@{ Type = 'vsan' }
                        }
                    },
                    [PSCustomObject]@{
                        Name = 'VSANDATASTORE'
                        ExtensionData = [PSCustomObject]@{
                            Summary = [PSCustomObject]@{ Type = 'vsan' }
                        }
                    }
                )
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item { } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management

            {
                Set-ToolsRepo `
                    -SourceDatastoreName 'vsanDatastore' `
                    -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                    -ExpectedHash ('A' * 64)
            } | Should -Throw -ExpectedMessage "*Multiple vSAN datastores matched source name 'vsanDatastore'*"

            Should -Not -Invoke New-Item -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management
        }

    }

    Context "Version and metadata decision logic (mock-only)" {
        if (-not (Get-Module Microsoft.AVS.Management)) {
            Import-Module (Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1") -Force
        }

        InModuleScope 'Microsoft.AVS.Management' {
            It "Should validate metadata indicators: <Case>" -TestCases @(
                @{
                    Case = 'collection active version matches'
                    MetadataJson = '{"version":"1.0","type":"collection","vmtools":"vmtools-13.0.5/","vmtools-12.5.4":"vmtools-12.5.4/"}'
                    LatestVersion = '13.0.5'
                    ExpectedResult = '13.0.5'
                },
                @{
                    Case = 'leaf active version matches'
                    MetadataJson = '{"version":"1.0","type":"leaf","installer":{"file":"VMware-tools-13.0.5-24915695-x64.exe","version":"13.0.5"}}'
                    LatestVersion = '13.0.5'
                    ExpectedResult = '13.0.5'
                },
                @{
                    Case = 'active version does not match'
                    MetadataJson = '{"version":"1.0","type":"collection","vmtools":"vmtools-12.5.4/","vmtools-13.0.5":"vmtools-13.0.5/"}'
                    LatestVersion = '13.0.5'
                    ExpectedResult = $null
                },
                @{
                    Case = 'metadata has no recognized active-version field'
                    MetadataJson = '{"version":"1.0","type":"collection","vmtools-12.5.4":"vmtools-12.5.4/"}'
                    LatestVersion = '13.0.5'
                    ExpectedResult = $null
                }
            ) {
                param($MetadataJson, $LatestVersion, $ExpectedResult)

                $metadataObject = $MetadataJson | ConvertFrom-Json

                $actualResult = Get-ToolsRepoMetadataVersion -MetadataObject $metadataObject -LatestVersion $LatestVersion
                if ($null -eq $ExpectedResult) {
                    $actualResult | Should -BeNullOrEmpty
                } else {
                    $actualResult | Should -Be $ExpectedResult
                }
            }

            BeforeAll {
                $script:originalTemp = $env:TEMP
                $script:originalTmp = $env:TMP
                $script:testTempDir = Join-Path $TestDrive 'temp'
                New-Item -Path $script:testTempDir -ItemType Directory -Force | Out-Null
                $env:TEMP = $script:testTempDir
                $env:TMP = $script:testTempDir

                # Shadow the real Get-EsxCli cmdlet with a plain function so Pester
                # can mock it without PowerCLI's VMHost[] type constraint blocking.
                function Get-EsxCli { param([switch]$V2, $VMHost) }

                function Initialize-SetToolsRepoScenarioMocks {
                    param(
                        [Parameter(Mandatory = $true)][string]$ToolsShortVersion,
                        [Parameter(Mandatory = $true)][string]$HighestExistingVersion,
                        [Parameter(Mandatory = $true)][bool]$VersionAlreadyExists,
                        [bool]$VersionMetadataExists = $true,
                        [bool]$IncludeFailingDatastore = $false,
                        [AllowNull()][object]$EsxCliResult = $true
                    )

                    $script:toolsVersion = "vmtools-$ToolsShortVersion"
                    $script:tempRoot = Join-Path $TestDrive 'newtools_test'
                    $script:sourceDir = Join-Path $TestDrive "vmtools-$ToolsShortVersion"
                    $script:topLevelSourceDir = Join-Path $script:tempRoot 'vmware' 'apps' 'vmtools' 'windows64'
                    $script:destPath = "DS:/GuestStore/vmware/apps/vmtools/windows64"
                    $script:versionDestPath = "$script:destPath/$script:toolsVersion"
                    $script:highestExistingVersion = $HighestExistingVersion
                    $script:versionAlreadyExists = $VersionAlreadyExists
                    $script:versionMetadataExists = $VersionMetadataExists
                    $script:includeFailingDatastore = $IncludeFailingDatastore
                    $script:esxCliResult = $EsxCliResult

                    # Create a fake extracted archive with matching metadata files under $TestDrive.
                    [System.IO.Directory]::CreateDirectory($script:topLevelSourceDir) | Out-Null
                    [System.IO.Directory]::CreateDirectory($script:sourceDir) | Out-Null
                    $script:collectionMetadataJson = @{
                        version = '1.0'
                        type = 'collection'
                        vmtools = "vmtools-$ToolsShortVersion/"
                        'vmtools-12.1.0' = 'vmtools-12.1.0/'
                    } | ConvertTo-Json -Compress
                    $script:leafMetadataJson = @{
                        version = '1.0'
                        type = 'leaf'
                        installer = @{
                            file = "VMware-tools-$ToolsShortVersion-24915695-x64.exe"
                            version = $ToolsShortVersion
                        }
                    } | ConvertTo-Json -Compress
                    [System.IO.File]::WriteAllText((Join-Path $script:topLevelSourceDir 'metadata.json'), $script:collectionMetadataJson)
                    [System.IO.File]::WriteAllText((Join-Path $script:sourceDir 'metadata.json'), $script:leafMetadataJson)

                    Mock New-Item {
                        [PSCustomObject]@{ FullName = $Path; Name = (Split-Path -Path $Path -Leaf) }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like 'DS:/*' }

                    Mock Get-Item { [PSCustomObject]@{ Length = 4096 } } -ModuleName Microsoft.AVS.Management
                    Mock Get-FileHash { [PSCustomObject]@{ Hash = ('A' * 64) } } -ModuleName Microsoft.AVS.Management
                    Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
                    Mock Get-Content {
                        $metadataPath = if ($LiteralPath) { $LiteralPath } else { $Path }
                        if ($metadataPath -eq (Join-Path $script:topLevelSourceDir 'metadata.json')) {
                            return $script:collectionMetadataJson
                        }

                        return $script:leafMetadataJson
                    } -ModuleName Microsoft.AVS.Management
                    Mock Join-Path {
                        if ($Path -like 'AVSToolsDs_*') {
                            return $script:destPath
                        }

                        return "$Path/$ChildPath"
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter {
                        $Path -like 'AVSToolsDs_*' -or $Path -like 'DS:*'
                    }

                    Mock Test-Path {
                        switch ($Path) {
                            "$script:tempRoot/tools.zip" { return $true }
                            $script:destPath { return $true }
                            $script:versionDestPath { return $script:versionAlreadyExists }
                            "$script:versionDestPath/metadata.json" { return $script:versionMetadataExists }
                            $script:topLevelSourceDir { return $true }
                            default { return $true }
                        }
                    } -ModuleName Microsoft.AVS.Management

                    Mock Get-ChildItem {
                        param(
                            $Path,
                            $Filter,
                            [switch]$Directory,
                            [switch]$File,
                            [switch]$Recurse
                        )

                        # vmtools-* directory discovery: production passes
                        # <tmp>\vmware\apps\vmtools\windows64\vmtools-* with -Directory
                        if ($Directory -and $Path -like '*windows64*') {
                            return @([PSCustomObject]@{ Name = $script:toolsVersion; FullName = $script:sourceDir })
                        }

                        # Existing datastore versions used to compute highestExistingVersion
                        if ($Path -eq $script:destPath -and -not $Filter -and -not $Recurse -and -not $File) {
                            return @([PSCustomObject]@{ Name = "vmtools-$script:highestExistingVersion"; FullName = "$script:destPath/vmtools-$script:highestExistingVersion"; PSIsContainer = $true })
                        }

                        # Source metadata is present so update path is testable
                        if ($Path -eq $script:sourceDir -and $Filter -eq 'metadata.json') {
                            return @([PSCustomObject]@{ Name = 'metadata.json'; FullName = "$script:sourceDir\metadata.json" })
                        }

                        # Copied version folder metadata check after Copy-DatastoreItem
                        if ($Path -eq $script:versionDestPath -and $Filter -eq 'metadata.json') {
                            return @([PSCustomObject]@{ Name = 'metadata.json'; FullName = "$script:versionDestPath/metadata.json" })
                        }

                        return @()
                    } -ModuleName Microsoft.AVS.Management

                    $script:browser = New-Object psobject
                    Add-Member -InputObject $script:browser -MemberType ScriptMethod -Name SearchDatastore -Value {
                        param($path, $spec)
                        return [PSCustomObject]@{ File = @([PSCustomObject]@{ FriendlyName = 'GuestStore' }) }
                    } -Force

                    Mock Get-View {
                        if ($Id -eq 'browser-fail') {
                            throw 'Datastore browser unavailable'
                        }

                        return $script:browser
                    } -ModuleName Microsoft.AVS.Management
                    Mock New-Object {
                        if ($TypeName -eq 'VMware.Vim.HostDatastoreBrowserSearchSpec') { return [PSCustomObject]@{ Query = @() } }
                        if ($TypeName -eq 'VMware.Vim.FolderFileQuery') { return [PSCustomObject]@{} }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter {
                        $TypeName -eq 'VMware.Vim.HostDatastoreBrowserSearchSpec' -or $TypeName -eq 'VMware.Vim.FolderFileQuery'
                    }

                    Mock Get-Datastore {
                        $datastores = @(
                            [PSCustomObject]@{
                                Name = 'vsanDatastore'
                                Id = 'Datastore-ds-123'
                                ExtensionData = [PSCustomObject]@{
                                    Browser = 'browser-1'
                                    Summary = [PSCustomObject]@{ Type = 'vsan'; Url = 'ds:///vmfs/volumes/vsanDatastore/' }
                                }
                            }
                        )

                        if ($script:includeFailingDatastore) {
                            $datastores += [PSCustomObject]@{
                                Name = 'vsanDatastore-fail'
                                Id = 'Datastore-ds-456'
                                ExtensionData = [PSCustomObject]@{
                                    Browser = 'browser-fail'
                                    Summary = [PSCustomObject]@{ Type = 'vsan'; Url = 'ds:///vmfs/volumes/vsanDatastore-fail/' }
                                }
                            }
                        }

                        return $datastores
                    } -ModuleName Microsoft.AVS.Management

                    Mock Get-PSDrive {
                        param($Name)

                        $lookupKey = "SetToolsRepoTestDrive-$Name"
                        if ([System.AppDomain]::CurrentDomain.GetData($lookupKey)) {
                            return [PSCustomObject]@{ Name = $Name }
                        }

                        return $null
                    } -ModuleName Microsoft.AVS.Management
                    Mock New-PSDrive {
                        param($Name)

                        $lookupKey = "SetToolsRepoTestDrive-$Name"
                        [System.AppDomain]::CurrentDomain.SetData($lookupKey, $true)
                        [PSCustomObject]@{ Name = $Name }
                    } -ModuleName Microsoft.AVS.Management
                    Mock Remove-PSDrive {
                        param($Name)

                        $lookupKey = "SetToolsRepoTestDrive-$Name"
                        [System.AppDomain]::CurrentDomain.SetData($lookupKey, $null)
                    } -ModuleName Microsoft.AVS.Management

                    Mock Get-VMHost {
                        return @(
                            [PSCustomObject]@{
                                Name = 'esx1'
                                ExtensionData = [PSCustomObject]@{ Datastore = [PSCustomObject]@{ value = @('ds-123') } }
                            }
                        )
                    } -ModuleName Microsoft.AVS.Management

                    $script:setObj = New-Object psobject
                    Add-Member -InputObject $script:setObj -MemberType ScriptMethod -Name CreateArgs -Value { return @{ url = $null } } -Force
                    Add-Member -InputObject $script:setObj -MemberType ScriptMethod -Name invoke -Value { param($arguments) return $script:esxCliResult } -Force
                    $script:esxcli = [PSCustomObject]@{
                        system = [PSCustomObject]@{
                            settings = [PSCustomObject]@{
                                gueststore = [PSCustomObject]@{
                                    repository = [PSCustomObject]@{ set = $script:setObj }
                                }
                            }
                        }
                    }
                    Mock Get-EsxCli {
                        param(
                            [switch]$V2,
                            [object]$VMHost
                        )

                        return $script:esxcli
                    } -ModuleName Microsoft.AVS.Management

                    Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
                }
            }

            AfterAll {
                Remove-Item -Path Function:Get-EsxCli -ErrorAction SilentlyContinue
                if ($null -ne $script:originalTemp) { $env:TEMP = $script:originalTemp }
                if ($null -ne $script:originalTmp)  { $env:TMP  = $script:originalTmp  }
            }

            It "Older version upload preserves top-level metadata.json" {
                $IncomingVersion = '12.3.0'
                $ExistingVersion = '12.4.0'
                Initialize-SetToolsRepoScenarioMocks -ToolsShortVersion $IncomingVersion -HighestExistingVersion $ExistingVersion -VersionAlreadyExists $false

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Not -Throw

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64'
                }
                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 0 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*metadata.json'
                }
                Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -Times 2 -Exactly -Scope It
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsSrc_*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsDs_*'
                }
            }

            It "Newer version upload updates top-level metadata.json" {
                Initialize-SetToolsRepoScenarioMocks `
                    -ToolsShortVersion '12.5.0' `
                    -HighestExistingVersion '12.4.0' `
                    -VersionAlreadyExists $false

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Not -Throw

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64'
                }
                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64/metadata.json'
                }
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsSrc_*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsDs_*'
                }
            }

            It "Should reject an existing version folder when metadata.json is missing" {
                Initialize-SetToolsRepoScenarioMocks `
                    -ToolsShortVersion '12.4.0' `
                    -HighestExistingVersion '12.4.0' `
                    -VersionAlreadyExists $true `
                    -VersionMetadataExists $false
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Throw -ExpectedMessage '*All datastores failed to process*'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*required metadata.json is missing*'
                }
                Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Destination -like '*GuestStore*'
                }
                Should -Not -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Scope It
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsSrc_*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsDs_*'
                }
            }

            It "Should fail the datastore when host repository configuration fails" {
                Initialize-SetToolsRepoScenarioMocks `
                    -ToolsShortVersion '12.3.0' `
                    -HighestExistingVersion '12.4.0' `
                    -VersionAlreadyExists $false
                Mock Get-EsxCli { throw 'ESXCLI unavailable' } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Throw -ExpectedMessage '*All datastores failed to process*vsanDatastore*ESXCLI unavailable*'

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64'
                }
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*esx1*' -and $Message -like '*ESXCLI unavailable*'
                }
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*Check the failed hosts for connectivity or ESXCLI issues*' -and
                    $Message -like '*rerun Set-ToolsRepo with the same parameters*' -and
                    $Message -like '*retry configuring the GuestStore repository on all hosts*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsSrc_*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsDs_*'
                }
            }

            It "Should fail when ESXCLI returns <Case>" -TestCases @(
                @{ Case = 'false'; EsxCliResult = $false },
                @{ Case = 'null'; EsxCliResult = $null }
            ) {
                param($EsxCliResult)

                Initialize-SetToolsRepoScenarioMocks `
                    -ToolsShortVersion '12.3.0' `
                    -HighestExistingVersion '12.4.0' `
                    -VersionAlreadyExists $false `
                    -EsxCliResult $EsxCliResult
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Throw -ExpectedMessage '*All datastores failed to process*'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*esx1*' -and
                    $Message -like '*ESXCLI failed to configure the GuestStore repository*'
                }
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*rerun Set-ToolsRepo with the same parameters*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsSrc_*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsDs_*'
                }
            }

            It "Should report partial failure when one datastore succeeds and another fails" {
                Initialize-SetToolsRepoScenarioMocks `
                    -ToolsShortVersion '12.3.0' `
                    -HighestExistingVersion '12.4.0' `
                    -VersionAlreadyExists $false `
                    -IncludeFailingDatastore $true
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management
                Mock Write-Error { } -ModuleName Microsoft.AVS.Management

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Throw -ExpectedMessage '*Some datastores failed to process*vsanDatastore-fail*Datastore browser unavailable*'

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64'
                }
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*vsanDatastore-fail*' -and $Message -like '*Datastore browser unavailable*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsSrc_*'
                }
                Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 2 -Exactly -Scope It -ParameterFilter {
                    $Name -like 'AVSToolsDs_*'
                }
                Should -Not -Invoke Write-Error -ModuleName Microsoft.AVS.Management -Scope It
            }

            It "Should report both datastore processing and destination PSDrive cleanup failures" {
                Initialize-SetToolsRepoScenarioMocks `
                    -ToolsShortVersion '12.3.0' `
                    -HighestExistingVersion '12.4.0' `
                    -VersionAlreadyExists $false
                Mock Get-View { throw 'Datastore browser unavailable' } -ModuleName Microsoft.AVS.Management
                Mock Remove-PSDrive {
                    param($Name)

                    if ($Name -like 'AVSToolsSrc_*') {
                        $lookupKey = "SetToolsRepoTestDrive-$Name"
                        [System.AppDomain]::CurrentDomain.SetData($lookupKey, $null)
                    }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                {
                    Set-ToolsRepo `
                        -SourceDatastoreName 'vsanDatastore' `
                        -ToolsZipPath 'AVS-ToolsRepo-Staging/tools.zip' `
                        -ExpectedHash ('A' * 64)
                } | Should -Throw -ExpectedMessage '*All datastores failed to process*'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Scope It -ParameterFilter {
                    $Message -like '*Datastore browser unavailable*' -and
                    $Message -like '*Additionally, cleanup failed*' -and
                    $Message -like '*Failed to remove temporary PSDrive*'
                }
            }

        }
    }

}

Describe "Get-EsxtopData" {
    Context "Parameter Validation" {
        It "Should have ClusterName as mandatory String parameter" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['ClusterName']
            $param.ParameterType.Name | Should -Be 'String'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $true
        }

        It "Should have EsxiHostName as mandatory String parameter" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['EsxiHostName']
            $param.ParameterType.Name | Should -Be 'String'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $true
        }

        It "Should have Iterations as optional Int32 with default 6" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['Iterations']
            $param.ParameterType.Name | Should -Be 'Int32'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $false
        }

        It "Should have IntervalSeconds as optional Int32 with ValidateRange(2,30)" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['IntervalSeconds']
            $param.ParameterType.Name | Should -Be 'Int32'
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr | Should -Not -BeNullOrEmpty
            $rangeAttr.MinRange | Should -Be 2
            $rangeAttr.MaxRange | Should -Be 30
        }

        It "Should have Iterations with ValidateRange(1,6)" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['Iterations']
            $rangeAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $rangeAttr | Should -Not -BeNullOrEmpty
            $rangeAttr.MinRange | Should -Be 1
            $rangeAttr.MaxRange | Should -Be 6
        }

        It "Should have OutputDatastoreName as optional String parameter" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['OutputDatastoreName']
            $param.ParameterType.Name | Should -Be 'String'
            ($param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -Be $false
        }

        It "Should have ValidateNotNullOrEmpty on ClusterName" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['ClusterName']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have ValidateNotNullOrEmpty on EsxiHostName" {
            $cmd = Get-Command Get-EsxtopData
            $param = $cmd.Parameters['EsxiHostName']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have HelpMessage on all parameters" {
            $cmd = Get-Command Get-EsxtopData
            foreach ($name in @('ClusterName', 'EsxiHostName', 'Iterations', 'IntervalSeconds', 'OutputDatastoreName')) {
                $param = $cmd.Parameters[$name]
                $paramAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
                $paramAttr.HelpMessage | Should -Not -BeNullOrEmpty -Because "$name should have HelpMessage"
            }
        }
    }

    Context "AVSAttribute Verification" {
        It "Should have AVSAttribute with 30 minute timeout" {
            $cmd = Get-Command Get-EsxtopData
            $avsAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 30
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $cmd = Get-Command Get-EsxtopData
            $avsAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }

        It "Should have AVSAttribute timeout <= 60 minutes" {
            $cmd = Get-Command Get-EsxtopData
            $avsAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.Timeout.TotalMinutes | Should -BeLessOrEqual 60
        }
    }

    Context "Sampling Span Validation" {
        BeforeEach {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when (Iterations-1)*IntervalSeconds exceeds 30" {
            { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -Iterations 6 -IntervalSeconds 7 } |
                Should -Throw -ExpectedMessage "*Esxtop sampling is limited to 30 seconds*"
        }

        It "Should not throw on sampling span validation when spacing equals 30" {
            Mock Get-Cluster { throw "Expected: past validation" } -ModuleName Microsoft.AVS.Management
            $err = $null
            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -Iterations 6 -IntervalSeconds 6 } catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Not -BeLike "*Esxtop sampling is limited*"
        }

        It "Should not throw on sampling span validation with single iteration" {
            Mock Get-Cluster { throw "Expected: past validation" } -ModuleName Microsoft.AVS.Management
            $err = $null
            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -Iterations 1 -IntervalSeconds 30 } catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Not -BeLike "*Esxtop sampling is limited*"
        }
    }

    Context "Host Resolution" {
        BeforeEach {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when cluster is not found" {
            Mock Get-Cluster { throw "Cluster 'BadCluster' not found." } -ModuleName Microsoft.AVS.Management
            { Get-EsxtopData -ClusterName 'BadCluster' -EsxiHostName 'host1' } |
                Should -Throw -ExpectedMessage "*BadCluster*"
        }

        It "Should throw when no matching connected host is found" {
            Mock Get-Cluster { [PSCustomObject]@{ Name = 'TestCluster' } } -ModuleName Microsoft.AVS.Management
            Mock Get-VMHost { return $null } -ModuleName Microsoft.AVS.Management
            { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'nohost' } |
                Should -Throw -ExpectedMessage "*No connected ESXi host matching*"
        }

    }

    Context "Input Sanitization" {
        It "Should call Limit-WildcardsandCodeInjectionCharacters for ClusterName and EsxiHostName" {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
            Mock Get-Cluster { throw "stop here" } -ModuleName Microsoft.AVS.Management

            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' } catch { }

            Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 2 -Exactly
        }

        It "Should sanitize OutputDatastoreName when provided" {
            Mock Limit-WildcardsandCodeInjectionCharacters { param($String) $String } -ModuleName Microsoft.AVS.Management
            Mock Get-Cluster { throw "stop here" } -ModuleName Microsoft.AVS.Management

            try { Get-EsxtopData -ClusterName 'TestCluster' -EsxiHostName 'host1' -OutputDatastoreName 'myDS' } catch { }

            Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 3 -Exactly
        }
    }

    Context "CmdletBinding" {
        It "Should have CmdletBinding attribute" {
            $cmd = Get-Command Get-EsxtopData
            $cmdletBindingAttr = $cmd.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
            $cmdletBindingAttr | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Classes.ps1 - Cross-SessionState Type Visibility" {
    <#
    Validates that AVSAttribute and AVSSecureFolder (both defined via Add-Type in Classes.ps1)
    are visible from a module SessionState that is different from the one in which Classes.ps1 was
    loaded. This is the exact scenario that broke with the old PowerShell 'class' keyword:

    When CDR's Import-ModulePinned calls Import-Module Microsoft.AVS.Management from inside a
    module function, ScriptsToProcess (Classes.ps1) runs in CDR's module SessionState. Any module
    that then dot-sources a .ps1 referencing [AVSAttribute] or [AVSSecureFolder] from its own
    SessionState would fail with 'Unable to find type' if those types were defined via 'class'.
    Add-Type registers types in the process AppDomain, making them visible everywhere.

    The test uses a subprocess (fresh pwsh) so that no prior Add-Type call in the current
    process's AppDomain can mask a regression.
    #>

    It "Vendor module dot-sourcing a .ps1 that references [AVSAttribute] and [AVSSecureFolder] imports successfully" {
        $cdrPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Microsoft.AVS.CDR' 'Microsoft.AVS.CDR.psd1')).Path
        $managementManifestPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Microsoft.AVS.Management' 'Microsoft.AVS.Management.psd1')).Path
        $managementVersion = [string](Import-PowerShellDataFile $managementManifestPath).ModuleVersion

        # CDR's Import-ModulePinned uses Get-PSResource, which only sees modules installed to the
        # PSResourceGet user/all-users scopes. Skip with a precondition message when the current
        # source version isn't installed (e.g. fresh laptop), so the test never silently no-ops.
        $installed = Get-PSResource -Name 'Microsoft.AVS.Management' -Version $managementVersion -ErrorAction SilentlyContinue
        if (-not $installed) {
            Set-ItResult -Skipped -Because "Microsoft.AVS.Management $managementVersion is not installed as a PSResource on this host. Install it (or run on a host that has it, e.g. CI) to exercise the cross-SessionState path."
            return
        }

        $escapedCdrPath = $cdrPath -replace "'", "''"
        $escapedManagementVersion = $managementVersion -replace "'", "''"

        # Reproduce the exact production shape that triggered the original bug:
        # CDR's Import-ModulePinned imports Management (Classes.ps1 runs in CDR's SessionState),
        # then a *vendor* module gets imported whose .psm1 dot-sources a .ps1 containing function
        # definitions decorated with [AVSAttribute(...)] and a body referencing [AVSSecureFolder].
        # With the old PowerShell `class` keyword, the parser fails to bind [AVSAttribute] when
        # dot-sourcing into the vendor's SessionState. With Add-Type, the AppDomain-registered
        # types resolve fine. Subprocess keeps the AppDomain clean to avoid masking a regression.
        $script = @"
`$ErrorActionPreference = 'Stop'

`$vendorRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avs-vendor-consumer-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path `$vendorRoot -Force | Out-Null

try {
    `$vendorImpl = Join-Path `$vendorRoot 'Vendor.Impl.ps1'
    `$vendorPsm1 = Join-Path `$vendorRoot 'Vendor.psm1'
    `$vendorPsd1 = Join-Path `$vendorRoot 'Vendor.psd1'

    Set-Content -Path `$vendorImpl -Encoding utf8 -Value @'
function Invoke-VendorAction {
    [CmdletBinding()]
    [AVSAttribute(5, UpdatesSDDC = `$false)]
    param()

    # Body references AVSSecureFolder to exercise type binding from a dot-sourced .ps1
    [void][AVSSecureFolder]
    'invoked'
}
'@

    Set-Content -Path `$vendorPsm1 -Encoding utf8 -Value '. (Join-Path `$PSScriptRoot ''Vendor.Impl.ps1'')'

    New-ModuleManifest -Path `$vendorPsd1 -RootModule 'Vendor.psm1' -ModuleVersion '1.0.0' ``
        -Guid ([guid]::NewGuid()) -FunctionsToExport @('Invoke-VendorAction') ``
        -CmdletsToExport @() -AliasesToExport @() -VariablesToExport @()

    Import-Module '$escapedCdrPath' -Force
    Import-ModulePinned -Name 'Microsoft.AVS.Management' -RequiredVersion '$escapedManagementVersion' -Force

    # Dot-source-with-AVSAttribute happens here. Fails at parse time under the old `class` design.
    Import-Module `$vendorPsd1 -Force

    `$cmd = Get-Command Invoke-VendorAction -ErrorAction Stop
    `$attr = `$cmd.ScriptBlock.Attributes | Where-Object { `$_.GetType().Name -eq 'AVSAttribute' } | Select-Object -First 1
    if (-not `$attr) { throw 'AVSAttribute was not bound on Invoke-VendorAction' }
    if (`$attr.Timeout.TotalMinutes -ne 5) { throw "Expected timeout 5, got `$(`$attr.Timeout.TotalMinutes)" }

    'ok'
}
finally {
    Remove-Item -Path `$vendorRoot -Recurse -Force -ErrorAction SilentlyContinue
}
"@
        $output = pwsh -NoProfile -NonInteractive -Command $script 2>&1
        $LASTEXITCODE | Should -Be 0 -Because (
            "Add-Type registers types in the AppDomain so dot-sourced .ps1 files in vendor module SessionStates can parse [AVSAttribute] and [AVSSecureFolder]. " +
            "stderr: $($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })"
        )
        $output | Should -Contain 'ok'
    }
}

Describe "Normalize-VCBannerText" {
    Context "Smart quote normalization" {
        It "Should replace smart quotes with ASCII quotes" {
            InModuleScope 'Microsoft.AVS.Management' {
                $input = ([char]0x201C) + "Authorized Users Only" + ([char]0x201D) + " and " + ([char]0x2018) + "AVS" + ([char]0x2019)
                $result = Normalize-VCBannerText -String $input

                $result | Should -Be '"Authorized Users Only" and ''AVS'''
            }
        }
    }

    Context "Special character cleanup" {
        It "Should remove unsafe symbols, keep line breaks, and normalize spaces" {
            InModuleScope 'Microsoft.AVS.Management' {
                $line1 = "Line1  with   spaces & `$ <tag> 😀"
                $line2 = "Line2    with    tabs"
                $input = $line1 + [Environment]::NewLine + $line2

                $result = Normalize-VCBannerText -String $input
                $expected = "Line1 with spaces tag" + [Environment]::NewLine + "Line2 with tabs"

                $result | Should -Be $expected
            }
        }
    }
}

Describe "Set-VCLoginBanner" {
    Context "SSH Session Validation" {
        It "Should throw when VC SSH session is unavailable" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $global:SSH_Sessions = $null
                Mock Invoke-SSHCommand {
                    throw "Invoke-SSHCommand should not be called"
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Throw -ExpectedMessage "*SSH session to vCenter is not available*"
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Happy Path" {
        It "Should configure banner successfully using primary commands" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 2
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "*mkdir -p*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    ($Command -like "*-enable_checkbox Y*" -or $Command -like "*-enable_checkbox N*")
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Fallback Path" {
        It "Should use file fallback when inline banner content command fails" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("inline content format failed")
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 2
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*mkdir -p*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*printf '%s'*" -and $Command -like "*>*message.txt*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and
                    $Command -like "*/message.txt*" -and
                    $Command -notlike "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*rm -rf --*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    ($Command -like "*-enable_checkbox Y*" -or $Command -like "*-enable_checkbox N*")
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Consent Fallback Path" {
        It "Should retry consent checkbox with Y/N when true/false format fails" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-enable_checkbox true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("true/false consent format failed")
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 2
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox Y"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "*mkdir -p*"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Enable Failure Path" {
        It "Should throw when final enable step fails and banner state cannot be verified" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("enable step failed")
                        }
                    }
                    if ($Command -like "*-get_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("get command not supported")
                        }
                    }
                    if ($Command -like "*-print_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("print command failed")
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Throw -ExpectedMessage "*Failed to verify banner state*"
                Should -Invoke Limit-WildcardsandCodeInjectionCharacters -ModuleName Microsoft.AVS.Management -Times 2
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    ($Command -like "*-enable_checkbox Y*" -or $Command -like "*-enable_checkbox N*")
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "*mkdir -p*"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Enable Verification Path" {
        It "Should succeed when enable command fails but get command returns banner content (legacy fallback)" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("enable step failed")
                        }
                    }
                    if ($Command -like "*-get_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @(
                                "Title: Notice",
                                "Content: Authorized use only."
                            )
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
        It "Should succeed when enable and get commands fail but print command returns banner content (legacy fallback)" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("enable step failed")
                        }
                    }
                    if ($Command -like "*-get_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("get command not supported")
                        }
                    }
                    if ($Command -like "*-print_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @(
                                "Title: Notice",
                                "Content: Authorized use only."
                            )
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
        It "Should throw when enable command fails and verification output has no banner content" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("enable step failed")
                        }
                    }
                    if ($Command -like "*-get_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("No banner configured")
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Throw -ExpectedMessage "*Banner enable failed: toggle command failed and banner content is empty*"
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Cleanup Guardrail Path (Optional)" {
        It "Should skip cleanup delete when fallback temp directory was not created" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("inline content failed")
                        }
                    }
                    if ($Command -like "*mkdir -p*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("mkdir failed")
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Throw -ExpectedMessage "*Failed to set login banner content using supported formats*"
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*mkdir -p*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "*rm -rf --*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "*printf '%s'*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*message.txt*"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Page Source Verification Path" {
        It "Should verify banner text in login page source via curl and not throw on success" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*-enable_checkbox true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*/usr/bin/curl*" -and $Command -like "*-k*" -and $Command -like "*-s*" -and $Command -like "*-L*" -and $Command -like "*https://localhost/ui/login*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @(
                                "<html><body>",
                                "<div>Notice</div>",
                                "<div>Authorized use only.</div>",
                                "</body></html>"
                            )
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "sudo -n /opt/vmware/bin/sso-config.sh *" -and
                    $Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable_checkbox true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable true"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*/usr/bin/curl*" -and $Command -like "*-k*" -and $Command -like "*-s*" -and $Command -like "*-L*" -and $Command -like "*https://localhost/ui/login*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner" -or
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }

        It "Should warn when login page source does not contain banner text but not throw" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*-enable_checkbox true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*/usr/bin/curl*" -and $Command -like "*-k*" -and $Command -like "*-s*" -and $Command -like "*-L*" -and $Command -like "*https://localhost/ui/login*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @(
                                "<html><body>",
                                "<div>No banner text here</div>",
                                "</body></html>"
                            )
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*/usr/bin/curl*" -and $Command -like "*https://localhost/ui/login*"
                }
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Message -like "*Login page source check did not find banner text*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner" -or
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }

        It "Should warn and not throw when curl check fails" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Limit-WildcardsandCodeInjectionCharacters {
                    param($String)
                    return $String
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*-enable_checkbox true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*-set_logon_banner -enable true*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    if ($Command -like "*/usr/bin/curl*" -and $Command -like "*-k*" -and $Command -like "*-s*" -and $Command -like "*-L*" -and $Command -like "*https://localhost/ui/login*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("curl failed")
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 0
                        Output = @("ok")
                        Error = @()
                    }
                } -ModuleName Microsoft.AVS.Management
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage "Authorized use only." -EnableConsent $true
                } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -like "*/usr/bin/curl*" -and $Command -like "*https://localhost/ui/login*"
                }
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Message -like "*Login page source check skipped: failed to fetch /ui/login via curl.*"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner" -or
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
    Context "Command Injection Safety" {
        # Regression guard for the fallback banner-file write. The value is user-controlled and
        # is single-quote escaped for a single shell parse. Wrapping it in an outer
        # /bin/sh -c "..." (double quotes) re-introduced a shell-injection break-out.
        It "Should not wrap fallback commands in a nested double-quoted /bin/sh -c and must keep the message single-quoted" {
            $originalSshSessions = $global:SSH_Sessions
            $global:VCBannerCapturedCommands = [System.Collections.Generic.List[string]]::new()
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                # Let the real sanitizers (Limit-WildcardsandCodeInjectionCharacters + Normalize-VCBannerText) run.
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    $global:VCBannerCapturedCommands.Add($Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        # Force the fallback (file) path.
                        return [PSCustomObject]@{ ExitStatus = 1; Output = @(); Error = @("inline content format failed") }
                    }
                    return [PSCustomObject]@{ ExitStatus = 0; Output = @("ok"); Error = @() }
                } -ModuleName Microsoft.AVS.Management

                # Message contains both a single quote and a double quote.
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage 'it''s "AVS"' -EnableConsent $true
                } | Should -Not -Throw

                $fileCmd = $global:VCBannerCapturedCommands | Where-Object { $_ -like "*printf '%s'*" -and $_ -like "*message.txt*" } | Select-Object -First 1
                $fileCmd | Should -Not -BeNullOrEmpty
                # No nested double-quoted shell wrapper.
                $global:VCBannerCapturedCommands | ForEach-Object { $_ | Should -Not -BeLike '*/bin/sh -c*' }
                # The message must stay inside single quotes.
                $fileCmd | Should -BeLike "*printf '%s' '*"
                # The user's single quote must be POSIX single-quote escaped ('"'"').
                $posix = "'" + '"' + "'" + '"' + "'"
                $fileCmd | Should -BeLike "*it$($posix)s*"
            }
            finally {
                Remove-Variable -Name VCBannerCapturedCommands -Scope Global -ErrorAction SilentlyContinue
                $global:SSH_Sessions = $originalSshSessions
            }
        }

        It "Should not execute injected commands when the fallback file-write runs in a real shell" -Skip:(-not ($IsLinux -or $IsMacOS)) {
            $originalSshSessions = $global:SSH_Sessions
            $global:VCBannerCapturedCommands = [System.Collections.Generic.List[string]]::new()
            $marker = Join-Path ([System.IO.Path]::GetTempPath()) ("avs-banner-inj-{0}" -f ([guid]::NewGuid().ToString('N')))
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    $global:VCBannerCapturedCommands.Add($Command)
                    if ($Command -like "*-set_logon_banner -title*" -and $Command -like "*-content*") {
                        return [PSCustomObject]@{ ExitStatus = 1; Output = @(); Error = @("inline content format failed") }
                    }
                    return [PSCustomObject]@{ ExitStatus = 0; Output = @("ok"); Error = @() }
                } -ModuleName Microsoft.AVS.Management

                # Payload uses only characters that survive sanitization (double quote + newline
                # + a plain command), attempting to break out and run `touch $marker`.
                $payload = "Notice`"`ntouch $marker`nprintf `""
                {
                    Set-VCLoginBanner -BannerTitle "Notice" -BannerMessage $payload -EnableConsent $true
                } | Should -Not -Throw

                $mkdirCmd = $global:VCBannerCapturedCommands | Where-Object { $_ -like "mkdir -p *" } | Select-Object -First 1
                $fileCmd  = $global:VCBannerCapturedCommands | Where-Object { $_ -like "*printf '%s'*" -and $_ -like "*message.txt*" } | Select-Object -First 1
                $mkdirCmd | Should -Not -BeNullOrEmpty
                $fileCmd  | Should -Not -BeNullOrEmpty

                # Reproduce exactly what the remote sshd does: run each captured command with a single shell parse.
                & '/bin/sh' '-c' $mkdirCmd
                & '/bin/sh' '-c' $fileCmd

                # If the escaping is broken, the injected `touch $marker` would have run.
                Test-Path -LiteralPath $marker | Should -BeFalse
            }
            finally {
                Get-ChildItem -Path ([System.IO.Path]::GetTempPath()) -Filter 'avs-login-banner-*' -Directory -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
                Remove-Variable -Name VCBannerCapturedCommands -Scope Global -ErrorAction SilentlyContinue
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
}
Describe "Get-VCLoginBanner" {
    Context "Fallback Path" {
        It "Should fallback to print command and set NamedOutputs when get command fails" {
            $originalSshSessions = $global:SSH_Sessions
            $originalNamedOutputs = $global:NamedOutputs
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                $global:NamedOutputs = @{}
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-get_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("get command not supported")
                        }
                    }
                    if ($Command -like "*-print_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @(
                                "Title: Notice",
                                "Message: Authorized use only.",
                                "Checkbox: true",
                                "Enabled: true"
                            )
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 1
                        Output = @()
                        Error = @("unexpected command")
                    }
                } -ModuleName Microsoft.AVS.Management
                { Get-VCLoginBanner } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
                $global:NamedOutputs | Should -Not -BeNullOrEmpty
                $global:NamedOutputs.ContainsKey("LoginBannerConfig") | Should -BeTrue
                $global:NamedOutputs["LoginBannerConfig"] | Should -BeLike "*Title: Notice*"
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
                $global:NamedOutputs = $originalNamedOutputs
            }
        }
    }

    Context "Sudo Permission Failure" {
        It "Should throw without publishing banner output when sudo denies both read commands" {
            $originalSshSessions = $global:SSH_Sessions
            $originalNamedOutputs = $global:NamedOutputs
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                $global:NamedOutputs = @{}
                Mock Write-VCSSHPermissionDiagnostic { } -ModuleName Microsoft.AVS.Management
                Mock Invoke-SSHCommand {
                    [PSCustomObject]@{
                        ExitStatus = 1
                        Output = @()
                        Error = @("sudo: a password is required")
                    }
                } -ModuleName Microsoft.AVS.Management

                { Get-VCLoginBanner } | Should -Throw -ExpectedMessage "*Failed to retrieve login banner configuration: sudo: a password is required*"

                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -get_logon_banner"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -print_logon_banner"
                }
                $global:NamedOutputs.ContainsKey("LoginBannerConfig") | Should -BeFalse
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
                $global:NamedOutputs = $originalNamedOutputs
            }
        }
    }

    Context "Session Validation" {
        It "Should throw when VC SSH session is missing" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $global:SSH_Sessions = @{}
                Mock Invoke-SSHCommand { } -ModuleName Microsoft.AVS.Management

                { Get-VCLoginBanner } | Should -Throw "*SSH session to vCenter is not available*"

                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
}
Describe "Remove-VCLoginBanner" {
    Context "Fallback Path" {
        It "Should retry with fallback disable command when primary disable command fails" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $mockSession = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([SSH.SshSession])
                $global:SSH_Sessions = @{
                    VC = [PSCustomObject]@{ Value = $mockSession }
                }
                Mock Invoke-SSHCommand {
                    param($SSHSession, $Command)
                    if ($Command -like "*-set_logon_banner -enable false*") {
                        return [PSCustomObject]@{
                            ExitStatus = 1
                            Output = @()
                            Error = @("primary disable failed")
                        }
                    }
                    if ($Command -like "*-disable_logon_banner*") {
                        return [PSCustomObject]@{
                            ExitStatus = 0
                            Output = @("ok")
                            Error = @()
                        }
                    }
                    return [PSCustomObject]@{
                        ExitStatus = 1
                        Output = @()
                        Error = @("unexpected command")
                    }
                } -ModuleName Microsoft.AVS.Management
                { Remove-VCLoginBanner } | Should -Not -Throw
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -set_logon_banner -enable false"
                }
                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                    $Command -eq "sudo -n /opt/vmware/bin/sso-config.sh -disable_logon_banner"
                }
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }

    Context "Session Validation" {
        It "Should throw when VC SSH session is missing" {
            $originalSshSessions = $global:SSH_Sessions
            try {
                $global:SSH_Sessions = @{}
                Mock Invoke-SSHCommand { } -ModuleName Microsoft.AVS.Management

                { Remove-VCLoginBanner } | Should -Throw "*SSH session to vCenter is not available*"

                Should -Invoke Invoke-SSHCommand -ModuleName Microsoft.AVS.Management -Times 0
            }
            finally {
                $global:SSH_Sessions = $originalSshSessions
            }
        }
    }
}
