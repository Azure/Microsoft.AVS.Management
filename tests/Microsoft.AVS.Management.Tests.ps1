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

# Keep synthetic-fixture analyzer suppressions off the legacy suite.
function Register-ManagementLoginTest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Exercises and restores the global session state consumed by workloads.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only synthetic canary credentials are used.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'The external SSO provider stub mirrors its legacy API.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'The external SSO provider accepts the legacy plaintext password argument.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'External transport stubs only record calls; they make no changes.')]
    param()

    Describe 'Management package login handlers' -Tag 'P1' {
    BeforeAll {
        $script:managementDirectory = Join-Path $PSScriptRoot '../Microsoft.AVS.Management'
        $script:rootModulePath = Join-Path $script:managementDirectory 'Microsoft.AVS.Management.psm1'
        $script:savedGlobals = @{}
        foreach ($name in 'DefaultVIServer', 'DefaultVIServers', 'MOB_Connection', 'SSH_Sessions',
            'SFTP_Sessions', 'PersistentSecrets', 'P1LoginCalls', 'P1LoginHosts') {
            $variable = Get-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
            $script:savedGlobals[$name] = @{ Exists = $null -ne $variable; Value = $variable.Value }
        }

        $global:P1LoginCalls = [System.Collections.Generic.List[object]]::new()
        $script:externalProvider = New-Module -Name P1.Login.External {
            function Add-LoginCall($Name, $Parameters) {
                $global:P1LoginCalls.Add([pscustomobject]@{ Name = $Name; Parameters = $Parameters })
            }
            function Connect-VIServer {
                [CmdletBinding()]
                param($Server, $Port, [pscredential]$Credential, [switch]$Force)
                Add-LoginCall 'VI' (@{}+$PSBoundParameters)
                $session = [pscustomobject]@{
                    Name = $Server
                    Port = $Port
                    IsConnected = $true
                    ServiceUri = [uri]"https://${Server}:$Port/sdk"
                    User = $Credential.UserName
                }
                $global:DefaultVIServer = $session
                $global:DefaultVIServers = @($session)
                $session
            }
            function Connect-SsoAdminServer {
                [CmdletBinding()]
                param($Server, $User, $Password, [switch]$SkipCertificateCheck)
                Add-LoginCall 'SSO' (@{}+$PSBoundParameters)
                [pscustomobject]@{ Name = $Server; User = $User }
            }
            function Get-VMHost {
                [CmdletBinding()]
                param()
                Add-LoginCall 'Hosts' @{}
                $global:P1LoginHosts
            }
            function New-SSHSession {
                [CmdletBinding()]
                param($ComputerName, [pscredential]$Credential, $KeyString, [switch]$AcceptKey)
                Add-LoginCall 'SSH' (@{}+$PSBoundParameters)
                [pscustomobject]@{ ComputerName = $ComputerName; Transport = 'SSH' }
            }
            function New-SFTPSession {
                [CmdletBinding()]
                param($ComputerName, [pscredential]$Credential, $KeyString, [switch]$AcceptKey)
                Add-LoginCall 'SFTP' (@{}+$PSBoundParameters)
                [pscustomobject]@{ ComputerName = $ComputerName; Transport = 'SFTP' }
            }
            Export-ModuleMember -Function Connect-VIServer, Connect-SsoAdminServer,
                Get-VMHost, New-SSHSession, New-SFTPSession
        }
        $script:mobProvider = New-Module -Name VMware.vSphere.SsoAdmin {
            function Connect-VcenterServerMOB {
                [CmdletBinding()]
                param($Server, [pscredential]$Credential, [switch]$SkipCertificateCheck)
                $global:P1LoginCalls.Add([pscustomobject]@{
                    Name = 'MOB'; Parameters = @{}+$PSBoundParameters
                })
                [pscustomobject]@{ Name = $Server; Kind = 'MOB' }
            }
            Export-ModuleMember -Function Connect-VcenterServerMOB
        }
        Import-Module $script:externalProvider -Global -Force
        Import-Module $script:mobProvider -Global -Force
        . (Join-Path $script:managementDirectory 'Classes.ps1')
        # Exercise the real root module without claiming its unavailable manifest dependencies.
        Import-Module $script:rootModulePath -Force -DisableNameChecking
    }

    AfterAll {
        Remove-Module Microsoft.AVS.Management -Force -ErrorAction SilentlyContinue
        Remove-Module $script:externalProvider, $script:mobProvider -Force -ErrorAction SilentlyContinue
        foreach ($name in $script:savedGlobals.Keys) {
            if ($script:savedGlobals[$name].Exists) {
                Set-Variable -Name $name -Value $script:savedGlobals[$name].Value -Scope Global
            } else {
                Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
            }
        }
    }

    BeforeEach {
        $global:P1LoginCalls.Clear()
        $global:DefaultVIServer = $null
        $global:DefaultVIServers = @()
        $global:MOB_Connection = 'previous-mob'
        $global:SSH_Sessions = 'previous-ssh'
        $global:SFTP_Sessions = 'previous-sftp'
        $global:PersistentSecrets = @{ Unrelated = 'keep-me' }
        $global:P1LoginHosts = @(
            [pscustomobject]@{ Name = 'esx-01' }
            [pscustomobject]@{ Name = 'worker-01' }
            [pscustomobject]@{ Name = 'odd-ESX-node' }
        )
        $script:inputs = @{
            Server = 'vc.invalid:8443'
            Credential = [pscredential]::new('vc-user', (ConvertTo-SecureString 'VC-PASSWORD-CANARY' -AsPlainText -Force))
            ApiToken = ConvertTo-SecureString 'TOKEN-CANARY' -AsPlainText -Force
            IdentityBrokerHostname = 'broker.invalid'
            Tenant = 'tenant-fixture'
            HostPassword = ConvertTo-SecureString 'HOST-PASSWORD-CANARY' -AsPlainText -Force
            Key = [string[]]@('KEY-CANARY', 'second-line')
        }
    }

    It 'exports the four independent login handlers' {
        foreach ($name in 'Connect-VC', 'Connect-SSOAdmin', 'Connect-MOB', 'Initialize-SSH') {
            Get-Command -Name $name -Module Microsoft.AVS.Management -ErrorAction Stop |
                Should -Not -BeNullOrEmpty
        }
    }

    It 'imports the root module without authenticating or replacing workload globals' {
        Import-Module $script:rootModulePath -Force -DisableNameChecking
        $global:P1LoginCalls.Count | Should -Be 0
        $global:MOB_Connection | Should -BeExactly 'previous-mob'
        $global:SSH_Sessions | Should -BeExactly 'previous-ssh'
        $global:SFTP_Sessions | Should -BeExactly 'previous-sftp'
        $global:PersistentSecrets.Unrelated | Should -BeExactly 'keep-me'
    }

    It 'accepts all seven inputs without exposing successful authentication output: <Handler>' -ForEach @(
        @{ Handler = 'Connect-VC' }
        @{ Handler = 'Connect-SSOAdmin' }
        @{ Handler = 'Connect-MOB' }
        @{ Handler = 'Initialize-SSH' }
    ) {
        @(& $Handler @script:inputs -Verbose -InformationAction Continue *>&1) | Should -BeNullOrEmpty
        $global:PersistentSecrets.Unrelated | Should -BeExactly 'keep-me'
        if ($Handler -ne 'Initialize-SSH') {
            $global:SSH_Sessions | Should -BeExactly 'previous-ssh'
            $global:SFTP_Sessions | Should -BeExactly 'previous-sftp'
        }
        if ($Handler -ne 'Connect-MOB') {
            $global:MOB_Connection | Should -BeExactly 'previous-mob'
        }
        foreach ($call in $global:P1LoginCalls) {
            $call.Parameters.Keys | Should -Not -Contain 'ApiToken'
            $call.Parameters.Keys | Should -Not -Contain 'IdentityBrokerHostname'
            $call.Parameters.Keys | Should -Not -Contain 'Tenant'
        }
    }

    It 'rejects a missing required credential without disclosing other inputs: <Handler>' -ForEach @(
        @{ Handler = 'Connect-VC' }
        @{ Handler = 'Connect-SSOAdmin' }
        @{ Handler = 'Connect-MOB' }
        @{ Handler = 'Initialize-SSH' }
    ) {
        $script:inputs.Credential = $null
        $failure = $null
        $records = [System.Collections.Generic.List[object]]::new()
        try {
            & $Handler @script:inputs -ErrorAction Stop *>&1 | ForEach-Object { $records.Add($_) }
        } catch { $failure = $_ }
        $failure | Should -Not -BeNullOrEmpty
        $failure.Exception.Message | Should -Match 'Credential'
        $failure.Exception.Message | Should -Not -Match 'CANARY'
        ($records | Out-String) | Should -Not -Match 'CANARY'
        $global:P1LoginCalls.Count | Should -Be 0
    }

    It 'adapts the legacy VI endpoint <Endpoint> to <HostName>:<Port>' -ForEach @(
        @{ Endpoint = 'vc.invalid:8443'; HostName = 'vc.invalid'; Port = 8443 }
        @{ Endpoint = 'vc.invalid'; HostName = 'vc.invalid'; Port = 443 }
        @{ Endpoint = 'vc.invalid:bad'; HostName = 'vc.invalid'; Port = 443 }
        @{ Endpoint = 'vc.invalid::8443'; HostName = 'vc.invalid'; Port = 8443 }
    ) {
        $script:inputs.Server = $Endpoint
        Connect-VC @script:inputs
        $global:P1LoginCalls.Count | Should -Be 1
        $call = $global:P1LoginCalls[0]
        $call.Name | Should -BeExactly 'VI'
        $call.Parameters.Server | Should -BeExactly $HostName
        $call.Parameters.Port | Should -Be $Port
        $call.Parameters.Credential.UserName | Should -BeExactly 'vc-user'
        $call.Parameters.Credential.GetNetworkCredential().Password | Should -BeExactly 'VC-PASSWORD-CANARY'
        $call.Parameters.Force | Should -BeTrue
        $call.Parameters.ErrorAction | Should -Be 'Stop'
    }

    It 'rejects an endpoint with more than two nonempty colon segments before connecting' {
        $script:inputs.Server = 'one:two:three'
        { Connect-VC @script:inputs } | Should -Throw '*Missing VC address*'
        $global:P1LoginCalls.Count | Should -Be 0
    }

    It 'reuses only a connected default session for the target host and port: <Case>' -ForEach @(
        @{ Case = 'matching'; HostName = 'VC.INVALID'; Port = 8443; Connected = $true; Connections = 0 }
        @{ Case = 'disconnected'; HostName = 'vc.invalid'; Port = 8443; Connected = $false; Connections = 1 }
        @{ Case = 'different host'; HostName = 'other.invalid'; Port = 8443; Connected = $true; Connections = 1 }
        @{ Case = 'different port'; HostName = 'vc.invalid'; Port = 443; Connected = $true; Connections = 1 }
    ) {
        $session = [pscustomobject]@{
            Name = $HostName; Port = $Port; IsConnected = $Connected
            ServiceUri = [uri]"https://${HostName}:$Port/sdk"; User = 'vc-user'
        }
        $global:DefaultVIServer = $session
        $global:DefaultVIServers = @($session)
        Connect-VC @script:inputs
        @($global:P1LoginCalls | Where-Object Name -eq VI).Count | Should -Be $Connections
    }

    It 'reuses a matching active VI session without requiring a credential' {
        $session = [pscustomobject]@{
            Name = 'vc.invalid'; Port = 8443; IsConnected = $true
            ServiceUri = [uri]'https://vc.invalid:8443/sdk'; User = 'vc-user'
        }
        $global:DefaultVIServer = $session
        $global:DefaultVIServers = @($session)
        $script:inputs.Remove('Credential')
        @(Connect-VC @script:inputs) | Should -BeNullOrEmpty
        $global:P1LoginCalls.Count | Should -Be 0
    }

    It 'initializes SSH discovery from an active VI session without a credential' {
        $session = [pscustomobject]@{
            Name = 'vc.invalid'; Port = 8443; IsConnected = $true
            ServiceUri = [uri]'https://vc.invalid:8443/sdk'; User = 'vc-user'
        }
        $global:DefaultVIServer = $session
        $global:DefaultVIServers = @($session)
        $script:inputs.Remove('Credential')
        @(Initialize-SSH @script:inputs) | Should -BeNullOrEmpty
        @($global:P1LoginCalls.Name) | Should -Be @('Hosts')
        $global:SSH_Sessions.ContainsKey('VC') | Should -BeTrue
        $global:SFTP_Sessions.ContainsKey('esx-01') | Should -BeTrue
        $global:SSH_Sessions['VC'].IsValueCreated | Should -BeFalse
        $global:SFTP_Sessions['esx-01'].IsValueCreated | Should -BeFalse
    }

    It 'establishes VI before discovery exactly once with <First> first' -ForEach @(
        @{ First = 'Connect-VC'; Second = 'Initialize-SSH' }
        @{ First = 'Initialize-SSH'; Second = 'Connect-VC' }
    ) {
        & $First @script:inputs
        & $Second @script:inputs
        @($global:P1LoginCalls.Name) | Should -Be @('VI', 'Hosts')
    }

    It 'preserves SSO endpoint and <PasswordCase> plaintext password independently of VI and MOB' -ForEach @(
        @{ PasswordCase = 'nonempty'; ExpectedPassword = 'VC-PASSWORD-CANARY' }
        @{ PasswordCase = 'empty'; ExpectedPassword = '' }
    ) {
        if ($PasswordCase -eq 'empty') {
            $script:inputs.Credential = [pscredential]::new('vc-user', [securestring]::new())
        }
        Connect-SSOAdmin @script:inputs
        $global:P1LoginCalls.Count | Should -Be 1
        $call = $global:P1LoginCalls[0]
        $call.Name | Should -BeExactly 'SSO'
        $call.Parameters.Server | Should -BeExactly 'vc.invalid:8443'
        $call.Parameters.User | Should -BeExactly 'vc-user'
        $call.Parameters.ContainsKey('Password') | Should -BeTrue
        $call.Parameters.Password | Should -BeExactly $ExpectedPassword
        $call.Parameters.SkipCertificateCheck | Should -BeTrue
        $global:DefaultVIServer | Should -BeNullOrEmpty
        $global:MOB_Connection | Should -BeExactly 'previous-mob'
    }

    It 'forwards an empty resolved password to VI without replacing it with the token' {
        $script:inputs.Credential = [pscredential]::new('vc-user', [securestring]::new())
        Connect-VC @script:inputs
        $global:P1LoginCalls[0].Parameters.Credential.Password.Length | Should -Be 0
    }

    It 'connects MOB through its expected provider and publishes only the global MOB connection' {
        Connect-MOB @script:inputs
        $global:P1LoginCalls.Count | Should -Be 1
        $call = $global:P1LoginCalls[0]
        $call.Name | Should -BeExactly 'MOB'
        $call.Parameters.Server | Should -BeExactly 'vc.invalid'
        $call.Parameters.Credential.UserName | Should -BeExactly 'vc-user'
        $call.Parameters.SkipCertificateCheck | Should -BeTrue
        $global:MOB_Connection.Name | Should -BeExactly 'vc.invalid'
        $global:MOB_Connection.Kind | Should -BeExactly 'MOB'
        $global:DefaultVIServer | Should -BeNullOrEmpty
        $global:SSH_Sessions | Should -BeExactly 'previous-ssh'
        $global:SFTP_Sessions | Should -BeExactly 'previous-sftp'
    }

    It 'warns rather than invoking a wrong-source MOB command or clearing an old connection' {
        function global:Connect-VcenterServerMOB { throw 'Wrong-source MOB connector must not run' }
        try {
            $warnings = @()
            @(Connect-MOB @script:inputs -WarningVariable warnings -WarningAction SilentlyContinue) |
                Should -BeNullOrEmpty
            $warnings.Count | Should -Be 1
            "$($warnings[0])" | Should -BeLike '*Connect-VcenterServerMOB is not available*'
            $global:P1LoginCalls.Count | Should -Be 0
            $global:MOB_Connection | Should -BeExactly 'previous-mob'
        } finally {
            Remove-Item Function:global:Connect-VcenterServerMOB -ErrorAction SilentlyContinue
            Import-Module $script:mobProvider -Global -Force
        }
    }

    It 'does nothing without a key, even without a credential' {
        $script:inputs.Remove('Key')
        $script:inputs.Remove('Credential')
        @(Initialize-SSH @script:inputs) | Should -BeNullOrEmpty
        $global:P1LoginCalls.Count | Should -Be 0
        $global:SSH_Sessions | Should -BeExactly 'previous-ssh'
        $global:SFTP_Sessions | Should -BeExactly 'previous-sftp'
    }

    It 'initializes lazy maps for a present empty key instead of treating it as absent' {
        $script:inputs.Key = [string[]]@()
        Initialize-SSH @script:inputs
        @($global:P1LoginCalls.Name) | Should -Be @('VI', 'Hosts')
        $global:SSH_Sessions.ContainsKey('VC') | Should -BeTrue
        $global:SFTP_Sessions.ContainsKey('esx-01') | Should -BeTrue
        $global:SSH_Sessions['VC'].IsValueCreated | Should -BeFalse
        $global:SSH_Sessions['VC'].Value.ComputerName | Should -BeExactly 'vc.invalid'
        $call = $global:P1LoginCalls | Where-Object Name -eq SSH
        $call.Parameters.ContainsKey('KeyString') | Should -BeTrue
        @($call.Parameters.KeyString).Count | Should -Be 0
    }

    It 'preserves duplicate-host replacement and case-sensitive host keys in both maps' {
        $global:P1LoginHosts = @(
            [pscustomobject]@{ Name = 'esx-01' }
            [pscustomobject]@{ Name = 'esx-01' }
            [pscustomobject]@{ Name = 'ESX-01' }
        )
        Initialize-SSH @script:inputs
        foreach ($sessions in $global:SSH_Sessions, $global:SFTP_Sessions) {
            $sessions.Count | Should -Be 3
            $sessions.ContainsKey('esx-01') | Should -BeTrue
            $sessions.ContainsKey('ESX-01') | Should -BeTrue
            $sessions['esx-01'].Value.ComputerName | Should -BeExactly 'esx-01'
            $sessions['ESX-01'].Value.ComputerName | Should -BeExactly 'ESX-01'
        }
    }

    It 'retains independent lazy SSH and SFTP closures with <PasswordCase> host password' -ForEach @(
        @{ PasswordCase = 'absent' }
        @{ PasswordCase = 'empty' }
        @{ PasswordCase = 'nonempty' }
    ) {
        switch ($PasswordCase) {
            'absent' { $script:inputs.Remove('HostPassword') }
            'empty' { $script:inputs.HostPassword = [securestring]::new() }
        }
        Initialize-SSH @script:inputs
        @($global:P1LoginCalls.Name) | Should -Be @('VI', 'Hosts')
        @($global:SSH_Sessions.Keys | Sort-Object) | Should -Be @('esx-01', 'odd-ESX-node', 'VC')
        @($global:SFTP_Sessions.Keys | Sort-Object) | Should -Be @('esx-01', 'odd-ESX-node', 'VC')
        foreach ($sessions in $global:SSH_Sessions, $global:SFTP_Sessions) {
            foreach ($target in 'VC', 'esx-01', 'odd-ESX-node') {
                $sessions[$target].IsValueCreated | Should -BeFalse
            }
        }

        $workload = New-Module -Name P1.Login.Workload {
            function Get-P1WorkloadSession {
                $global:SSH_Sessions['esx-01'].Value
                $global:SFTP_Sessions['odd-ESX-node'].Value
            }
            Export-ModuleMember -Function Get-P1WorkloadSession
        }
        Import-Module $workload
        try {
            @(Get-P1WorkloadSession | ForEach-Object ComputerName) | Should -Be @('esx-01', 'odd-ESX-node')
            foreach ($sessions in $global:SSH_Sessions, $global:SFTP_Sessions) {
                foreach ($target in 'VC', 'esx-01', 'odd-ESX-node') {
                    $first = $sessions[$target].Value
                    $second = $sessions[$target].Value
                    [object]::ReferenceEquals($first, $second) | Should -BeTrue
                    $expectedTarget = if ($target -eq 'VC') { 'vc.invalid' } else { $target }
                    $first.ComputerName | Should -BeExactly $expectedTarget
                }
            }
        } finally {
            Remove-Module $workload -Force
        }

        $connections = @($global:P1LoginCalls | Where-Object Name -in SSH, SFTP)
        $connections.Count | Should -Be 6
        foreach ($call in $connections) {
            $parameters = $call.Parameters
            $parameters.Credential.UserName | Should -BeExactly ([Environment]::UserName)
            $parameters.AcceptKey | Should -BeTrue
            $expectedPassword = if ($PasswordCase -eq 'nonempty') { 'HOST-PASSWORD-CANARY' } else { '' }
            $parameters.Credential.GetNetworkCredential().Password | Should -BeExactly $expectedPassword
            $hasKey = $parameters.ComputerName -eq 'vc.invalid' -or $PasswordCase -ne 'nonempty'
            $parameters.ContainsKey('KeyString') | Should -Be $hasKey
            if ($hasKey) {
                @($parameters.KeyString) | Should -Be @('KEY-CANARY', 'second-line')
            }
        }
        $global:PersistentSecrets.Unrelated | Should -BeExactly 'keep-me'
    }

    It 'declares the complete login metadata against exported non-workload helpers without changing pins' {
        $manifest = Import-PowerShellDataFile (Join-Path $script:managementDirectory 'Microsoft.AVS.Management.psd1')
        $metadata = $manifest.PrivateData.PSData
        $metadata.LoginContract | Should -Be 1
        $metadata.Logins | Should -BeOfType [hashtable]
        @($metadata.Logins.Keys | Sort-Object) | Should -Be @('MOB', 'SSH', 'SSO', 'vCenter')
        $expected = @{
            vCenter = 'Connect-VC'
            SSO = 'Connect-SSOAdmin'
            MOB = 'Connect-MOB'
            SSH = 'Initialize-SSH'
        }
        foreach ($id in $expected.Keys) {
            $name = $expected[$id]
            $metadata.Logins[$id] | Should -BeExactly $name
            @($metadata.Logins.Values | Where-Object { $_ -eq $name }).Count | Should -Be 1
            @($manifest.FunctionsToExport | Where-Object { $_ -eq $name }).Count | Should -Be 1
            $command = Get-Command -Name $name -Module Microsoft.AVS.Management -ErrorAction Stop
            @($command.ScriptBlock.Attributes | Where-Object { $_ -is [AVSAttribute] }).Count | Should -Be 0
        }
        @($manifest.RequiredModules | ForEach-Object {
            "$($_.ModuleName):$($_.RequiredVersion):$($_.ModuleVersion)"
        }) | Should -Be @(
            'VMware.vSphere.SsoAdmin:1.4.0:'
            'VMware.VimAutomation.Core:13.3.0.24145081:'
            'VMware.VimAutomation.Storage:13.3.0.24145081:'
            'Posh-SSH::3.2.7'
        )
    }

    It 'preserves custom manifest metadata when stamping <Scenario>' -ForEach @(
        @{ Scenario = 'a new prerelease'; InitialSuffix = $null; RequestedSuffix = 'preview-test'; ExpectedSuffix = 'preview-test' }
        @{ Scenario = 'an existing prerelease'; InitialSuffix = 'previous'; RequestedSuffix = 'preview-test'; ExpectedSuffix = 'preview-test' }
        @{ Scenario = 'without a prerelease argument'; InitialSuffix = 'previous'; RequestedSuffix = ''; ExpectedSuffix = 'previous' }
        @{ Scenario = 'with a blank prerelease argument'; InitialSuffix = 'previous'; RequestedSuffix = ' '; ExpectedSuffix = 'previous' }
    ) {
        $path = Join-Path $TestDrive 'ManifestStamp.psd1'
        $content = @'
@{
    ModuleVersion = '12.0.0'
    GUID = '11111111-2222-4333-8444-555555555555'
    Author = 'Manifest test fixture'
    Description = 'Metadata preservation fixture'
    PrivateData = @{
        PSData = @{
            Logins = @{ vCenter = 'Connect-VC'; SSH = 'Initialize-SSH' }
            LoginContract = 1
            CustomMetadata = @{
                ModuleVersion = 'unchanged-nested-version'
                Prerelease = 'unchanged-nested-suffix'
            }
            # Prerelease = ''
        }
    }
}
'@
        if ($null -ne $InitialSuffix) {
            $content = $content.Replace("# Prerelease = ''", "Prerelease = '$InitialSuffix'")
        }
        Set-Content -LiteralPath $path -Value $content
        $before = Import-PowerShellDataFile $path
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot '../.build-tools/publish.ps1'), [ref]$tokens, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty
        $update = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'update-moduleversion'
        }, $true).Body.GetScriptBlock()
        & {
            param($ManifestPath, $Suffix, $UpdateBody)
            $absolutePathToManifest = $ManifestPath
            $buildNumber = '42'
            $prereleaseString = $Suffix
            & $UpdateBody | Out-Null
        } $path $RequestedSuffix $update

        $after = Import-PowerShellDataFile $path
        $after.PrivateData.PSData.Logins | Should -Not -BeNullOrEmpty
        $after.PrivateData.PSData.LoginContract | Should -Be 1
        $after.ModuleVersion | Should -BeExactly '12.0.42'
        $after.PrivateData.PSData.Prerelease | Should -BeExactly $ExpectedSuffix
        $before.Remove('ModuleVersion')
        $after.Remove('ModuleVersion')
        $before.PrivateData.PSData.Remove('Prerelease')
        $after.PrivateData.PSData.Remove('Prerelease')
        [System.Text.Json.Nodes.JsonNode]::DeepEquals(
            [System.Text.Json.Nodes.JsonNode]::Parse(($before | ConvertTo-Json -Depth 20)),
            [System.Text.Json.Nodes.JsonNode]::Parse(($after | ConvertTo-Json -Depth 20))
        ) | Should -BeTrue
    }

    It 'stamps the repository module manifests without changing their other fields' {
        $repository = Split-Path $script:managementDirectory
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $repository '.build-tools/publish.ps1'), [ref]$tokens, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty
        $update = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'update-moduleversion'
        }, $true).Body.GetScriptBlock()
        foreach ($name in 'Microsoft.AVS.Management', 'Microsoft.AVS.CDR', 'Microsoft.AVS.NFS', 'Microsoft.AVS.VMFS') {
            $path = Join-Path $TestDrive "$name.psd1"
            Copy-Item -LiteralPath (Join-Path $repository $name "$name.psd1") -Destination $path
            $before = Import-PowerShellDataFile $path
            $version = [version]$before.ModuleVersion
            & {
                param($ManifestPath, $UpdateBody)
                $absolutePathToManifest = $ManifestPath
                $buildNumber = '42'
                $prereleaseString = 'preview-test'
                & $UpdateBody | Out-Null
            } $path $update
            $after = Import-PowerShellDataFile $path
            $after.ModuleVersion | Should -BeExactly "$($version.Major).$($version.Minor).42"
            $after.PrivateData.PSData.Prerelease | Should -BeExactly 'preview-test'
            $before.Remove('ModuleVersion')
            $after.Remove('ModuleVersion')
            $before.PrivateData.PSData.Remove('Prerelease')
            $after.PrivateData.PSData.Remove('Prerelease')
            [System.Text.Json.Nodes.JsonNode]::DeepEquals(
                [System.Text.Json.Nodes.JsonNode]::Parse(($before | ConvertTo-Json -Depth 20)),
                [System.Text.Json.Nodes.JsonNode]::Parse(($after | ConvertTo-Json -Depth 20))
            ) | Should -BeTrue
        }
    }

    It 'keeps real handlers globally available after a selected transitive CDR import with synthetic providers' {
        $fixtureRoot = Join-Path $TestDrive 'login-dependencies'
        $manifest = Import-PowerShellDataFile (Join-Path $script:managementDirectory 'Microsoft.AVS.Management.psd1')

        function New-LoginDependencyFixture($Name, $Version, $Body, $Dependencies = @()) {
            $directory = Join-Path $fixtureRoot $Name $Version
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $directory "$Name.psm1") -Value $Body
            New-ModuleManifest -Path (Join-Path $directory "$Name.psd1") -RootModule "$Name.psm1" `
                -ModuleVersion $Version -RequiredModules $Dependencies -FunctionsToExport '*' `
                -CmdletsToExport @() -AliasesToExport @()
        }

        $providerBodies = @{
            'VMware.VimAutomation.Core' = @'
function Connect-VIServer { $global:P1FixtureAuthCalls++; throw 'Unexpected VI authentication' }
function Get-VMHost { $global:P1FixtureDiscoveries++; [pscustomobject]@{ Name = 'esx-fixture' } }
'@
            'VMware.vSphere.SsoAdmin' = @'
function Connect-SsoAdminServer { $global:P1FixtureAuthCalls++; throw 'Unexpected SSO authentication' }
function Connect-VcenterServerMOB { $global:P1FixtureAuthCalls++; throw 'Unexpected MOB authentication' }
'@
            'VMware.VimAutomation.Storage' = ''
            'Posh-SSH' = @'
function New-SSHSession {
    param($ComputerName, [pscredential]$Credential, $KeyString, [switch]$AcceptKey)
    $global:P1FixtureTransportCalls++
    [pscustomobject]@{ ComputerName = $ComputerName; Transport = 'SSH' }
}
function New-SFTPSession {
    param($ComputerName, [pscredential]$Credential, $KeyString, [switch]$AcceptKey)
    $global:P1FixtureTransportCalls++
    [pscustomobject]@{ ComputerName = $ComputerName; Transport = 'SFTP' }
}
'@
        }
        foreach ($dependency in $manifest.RequiredModules) {
            $version = if ($dependency.RequiredVersion) { $dependency.RequiredVersion } else { $dependency.ModuleVersion }
            New-LoginDependencyFixture $dependency.ModuleName $version $providerBodies[$dependency.ModuleName]
        }

        # Stage the package unchanged; synthetic providers satisfy its original manifest pins.
        $managementVersion = [string]$manifest.ModuleVersion
        $managementStage = Join-Path $fixtureRoot 'Microsoft.AVS.Management' $managementVersion
        New-Item -Path $managementStage -ItemType Directory -Force | Out-Null
        Copy-Item -Path (Join-Path $script:managementDirectory '*') -Destination $managementStage -Recurse
        New-LoginDependencyFixture 'P1.Login.Middle' '1.0.0' '' @(
            @{ ModuleName = 'Microsoft.AVS.Management'; RequiredVersion = $managementVersion }
        )
        New-LoginDependencyFixture 'P1.Login.SelectedWorkload' '1.0.0' @'
function Invoke-P1SelectedWorkload {
    $global:SSH_Sessions['VC'].Value
    $global:SFTP_Sessions['esx-fixture'].Value
}
'@ @(@{ ModuleName = 'P1.Login.Middle'; RequiredVersion = '1.0.0' })

        $originalModulePath = $env:PSModulePath
        $shell = [powershell]::Create()
        try {
            $shell.AddScript({
                param($FixtureRoot, $CdrManifest)
                $ErrorActionPreference = 'Stop'
                $env:PSModulePath = $FixtureRoot + [IO.Path]::PathSeparator + $env:PSModulePath
                $global:P1FixtureAuthCalls = 0
                $global:P1FixtureDiscoveries = 0
                $global:P1FixtureTransportCalls = 0
                $global:P1FixtureInventory = @{}
                foreach ($path in Get-ChildItem -LiteralPath $FixtureRoot -Filter '*.psd1' -Recurse) {
                    $data = Import-PowerShellDataFile $path.FullName
                    $dependencies = @(foreach ($dependency in $data.RequiredModules) {
                        $range = if ($dependency.RequiredVersion) { "[$($dependency.RequiredVersion)]" } else { "[$($dependency.ModuleVersion),)" }
                        [pscustomobject]@{ Name = $dependency.ModuleName; VersionRange = $range }
                    })
                    $global:P1FixtureInventory[$path.BaseName] = [pscustomobject]@{
                        Name = $path.BaseName; Version = [version]$data.ModuleVersion
                        InstalledLocation = $FixtureRoot; Dependencies = $dependencies
                    }
                }
                # Only the external installed-resource inventory is synthetic, not CDR resolution/import.
                function global:Get-InstalledPSResource {
                    param($Name, $Version)
                    $resource = $global:P1FixtureInventory[$Name]
                    if ($resource -and (-not $Version -or "$($resource.Version)" -eq $Version)) { $resource }
                }
                Import-Module $CdrManifest -Force
                $names = 'Connect-VC', 'Connect-SSOAdmin', 'Connect-MOB', 'Initialize-SSH'
                $alreadyImported = @(Get-Command -ListImported | Where-Object Name -in $names)
                if ($alreadyImported.Count) {
                    throw "Handlers were already imported before the dependency loader: $($alreadyImported | ForEach-Object { "$($_.Name)@$($_.ModuleName)" })"
                }
                $resolved = @(Get-PSResourcesPinned -Name P1.Login.SelectedWorkload -RequiredVersion 1.0.0)
                $loader = New-Module -Name P1.Login.DependencyLoader {
                    function Import-P1SelectedWorkload {
                        Import-ModulePinned -Name P1.Login.SelectedWorkload -RequiredVersion 1.0.0 -Force
                    }
                    Export-ModuleMember -Function Import-P1SelectedWorkload
                }
                Import-Module $loader
                Import-P1SelectedWorkload
                Remove-Module $loader -Force
                $commands = @(Get-Command -ListImported | Where-Object {
                    $_.Name -in $names -and $_.ModuleName -eq 'Microsoft.AVS.Management'
                })
                $importWasIdle = $global:P1FixtureAuthCalls -eq 0 -and
                    $global:P1FixtureDiscoveries -eq 0 -and $global:P1FixtureTransportCalls -eq 0
                $global:DefaultVIServer = [pscustomobject]@{ Name = 'vc.invalid'; Port = 8443; IsConnected = $true }
                $global:DefaultVIServers = @($global:DefaultVIServer)
                Initialize-SSH -Server 'vc.invalid:8443' -Key @('fixture-key')
                $transportsBeforeWorkload = $global:P1FixtureTransportCalls
                $workload = Get-Command Invoke-P1SelectedWorkload -ListImported -ErrorAction Stop
                $sessions = @(& $workload)
                [pscustomobject]@{
                    Helpers = @($commands.Name | Sort-Object)
                    Resolved = @($resolved.Name)
                    ImportWasIdle = $importWasIdle
                    TransportsBeforeWorkload = $transportsBeforeWorkload
                    Discoveries = $global:P1FixtureDiscoveries
                    AuthCalls = $global:P1FixtureAuthCalls
                    Targets = @($sessions.ComputerName)
                    Transports = @($sessions.Transport)
                    TransportCalls = $global:P1FixtureTransportCalls
                }
            }.ToString()).AddArgument($fixtureRoot).AddArgument(
                (Join-Path $PSScriptRoot '../Microsoft.AVS.CDR/Microsoft.AVS.CDR.psd1')) | Out-Null
            $result = @($shell.Invoke())
            $shell.Streams.Error | Should -BeNullOrEmpty
            $result.Count | Should -Be 1
            $result[0].Helpers | Should -Be @('Connect-MOB', 'Connect-SSOAdmin', 'Connect-VC', 'Initialize-SSH')
            $result[0].Resolved | Should -Contain 'P1.Login.Middle'
            $result[0].Resolved | Should -Contain 'Microsoft.AVS.Management'
            $result[0].Resolved[-1] | Should -BeExactly 'P1.Login.SelectedWorkload'
            $result[0].ImportWasIdle | Should -BeTrue
            $result[0].AuthCalls | Should -Be 0
            $result[0].Discoveries | Should -Be 1
            $result[0].TransportsBeforeWorkload | Should -Be 0
            $result[0].Targets | Should -Be @('vc.invalid', 'esx-fixture')
            $result[0].Transports | Should -Be @('SSH', 'SFTP')
            $result[0].TransportCalls | Should -Be 2
        } finally {
            $shell.Dispose()
            $env:PSModulePath = $originalModulePath
        }
    }
    }
}

Register-ManagementLoginTest
