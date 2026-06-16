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
    BeforeAll {
        # Helper function to create SecureString from plain text for testing
        function ConvertTo-TestSecureString {
            param([string]$PlainText)
            return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
        }
    }

    Context "Parameter Validation" {
        It "Should throw when neither ToolsURL nor Validate is provided" {
            { Set-ToolsRepo } |
                Should -Throw -ExpectedMessage "*ToolsURL is required when -Validate is not specified*"
        }

        It "Should skip URL validation and complete validate mode successfully" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) {
                    return $ChildPath
                }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                @([PSCustomObject]@{ Name = "vmtools-12.0.0"; PSIsContainer = $true })
            } -ModuleName Microsoft.AVS.Management
            Mock New-Item {
                [PSCustomObject]@{
                    FullName = (Join-Path -Path $TestDrive -ChildPath "avs-validate-test")
                }
            } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.0.0"}'
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

            $invalidUrl = ConvertTo-TestSecureString "not-a-valid-url"

            { Set-ToolsRepo -ToolsURL $invalidUrl -Validate } |
                Should -Not -Throw

            # Verify function entered validate mode by checking Get-Datastore was called
            Should -Invoke Get-Datastore -ModuleName Microsoft.AVS.Management -Times 1

            # Verify URL validation was SKIPPED (Invoke-WebRequest should NOT be called)
            Should -Not -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management
        }
    }

    Context "Error Handling" {
        It "Should wrap download failure in descriptive message" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest {
                throw "Permission denied"
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to download tools file*Permission denied*"
        }

        It "Should re-throw after catching to propagate error" {
            Mock Invoke-WebRequest { throw "Network error" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Throw -ExpectedMessage "*Unable to access the provided URL*Network error*"
        }
    }

    Context "PSDrive Cleanup" {
        It "Should attempt PSDrive cleanup even when PSDrive creation fails" {
            $IncomingVersion = '12.3.0'
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{
                    Name = "vmtools-$IncomingVersion"
                    FullName = "$TestDrive/vmware/apps/vmtools/windows64/vmtools-$IncomingVersion"
                }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore {
                [PSCustomObject]@{
                    Name = "vsanDatastore"
                    ExtensionData = [PSCustomObject]@{ Summary = [PSCustomObject]@{ Type = 'vsan' } }
                }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { [PSCustomObject]@{ Name = 'DS'; Root = 'DS:/' } } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { throw "PSDrive creation failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Name -eq 'DS' }

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            # Verify error is thrown and cleanup still happens
            { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Throw -ExpectedMessage "*All datastores failed to process*"

            # Verify cleanup was attempted despite the error
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -ParameterFilter { $Name -eq 'DS' }
        }
    }



    Context "Validate Mode Behavior" {
        It "Should not call upload/download functions when -Validate is specified" {
            # Mock functions that would be called for datastore reading
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) {
                    return $ChildPath
                }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                @([PSCustomObject]@{ Name = "vmtools-12.0.0"; PSIsContainer = $true })
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.0.0"}'
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

            # These should NEVER be called in validate mode
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            # Validate mode copies only metadata.json files locally for parsing.
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management

            # Call validate mode
            { Set-ToolsRepo -Validate } | Should -Not -Throw

            # Verify the upload/download functions were never called
            Should -Invoke Invoke-WebRequest -Times 0 -ModuleName Microsoft.AVS.Management
            Should -Invoke Expand-Archive -Times 0 -ModuleName Microsoft.AVS.Management
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
        }

        It "Should select highest vmtools version folder in validate mode" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
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
                    [PSCustomObject]@{ Name = "vmtools-12.3.0"; PSIsContainer = $true },
                    [PSCustomObject]@{ Name = "vmtools-12.2.0"; PSIsContainer = $true }
                )
            } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.3.0","path":"vmtools-12.3.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.3.0","path":"vmtools-12.3.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            { Set-ToolsRepo -Validate } | Should -Not -Throw

            Should -Invoke Write-Host -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like "*latest detected tools version: vmtools-12.3.0*"
            }
            Should -Invoke Copy-DatastoreItem -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*vmtools-12.3.0*metadata.json"
            }
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management
        }

        It "Should succeed when metadata files are in sync and reference latest version" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
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
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.3.0","path":"vmtools-12.3.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.3.0","path":"vmtools-12.3.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            { Set-ToolsRepo -Validate } | Should -Not -Throw

            Should -Invoke Write-Host -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like "*validation result: SUCCESS*"
            }
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
        }

        It "Should report FAILURE when top-level and version metadata do not match" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Write-Host { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) { return $ChildPath }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*metadata.json" -or $Path -like "*GuestStore*" }
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
                '{"version":"12.3.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.2.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            # When all datastores fail validation, function throws
            { Set-ToolsRepo -Validate } | Should -Throw -ExpectedMessage "*Validation failed for all datastores*"

            Should -Invoke Write-Host -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like "*validation result: FAILURE*"
            }
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
        }

        It "Should report FAILURE when metadata matches but does not reference latest version" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Write-Host { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) { return $ChildPath }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*metadata.json" -or $Path -like "*GuestStore*" }
            Mock Get-ChildItem {
                @(
                    [PSCustomObject]@{ Name = "vmtools-12.2.0"; PSIsContainer = $true },
                    [PSCustomObject]@{ Name = "vmtools-12.3.0"; PSIsContainer = $true }
                )
            } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            # Metadata is in sync (both say 12.2.0) but points to old version (not latest 12.3.0)
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.2.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content {
                param($Path, [switch]$Raw)
                '{"version":"12.2.0"}'
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            { Set-ToolsRepo -Validate } | Should -Throw -ExpectedMessage "*Validation failed for all datastores*"

            Should -Invoke Write-Host -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Object -like "*validation result: FAILURE*"
            }
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
        }

        It "Should fail when GuestStore tools path is missing" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Write-Error { } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) { return $ChildPath }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $false } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*GuestStore*" }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management  # Default for metadata files and other paths

            { Set-ToolsRepo -Validate } | Should -Throw -ExpectedMessage "*Validation failed for all datastores*"

            Should -Invoke Write-Error -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Message -like "*GuestStore tools path not found on vsanDatastore*"
            }
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management
        }

        It "Should fail when top-level metadata.json is missing" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Write-Error { } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) { return $ChildPath }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path {
                param($Path)
                # Base tools path exists, but metadata.json files do not
                return $Path -notlike "*metadata.json"
            } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                @([PSCustomObject]@{ Name = "vmtools-12.3.0"; PSIsContainer = $true })
            } -ModuleName Microsoft.AVS.Management

            { Set-ToolsRepo -Validate } | Should -Throw -ExpectedMessage "*Validation failed for all datastores*"

            Should -Invoke Write-Error -Times 1 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Message -like "*Top-level metadata.json not found on vsanDatastore*"
            }
            Should -Not -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management
        }

        It "Should prioritize -Validate when both ToolsURL and Validate are provided" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Write-Host { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path {
                param($Path, $ChildPath)
                if ([string]::IsNullOrEmpty($Path)) { return $ChildPath }
                return "$Path/$ChildPath"
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*metadata.json" -or $Path -like "*vmtools*" }
            Mock Get-ChildItem {
                @(
                    [PSCustomObject]@{ Name = "vmtools-12.2.0"; PSIsContainer = $true },
                    [PSCustomObject]@{ Name = "vmtools-12.3.0"; PSIsContainer = $true }
                )
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Content { '{"version":"12.3.0","path":"vmtools-12.3.0"}' } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*top-level-metadata.json" }
            Mock Get-Content { '{"version":"12.3.0","path":"vmtools-12.3.0"}' } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like "*version-metadata.json" }

            # Upload-mode functions must not run when -Validate is supplied.
            Mock Invoke-WebRequest { throw "Should not call web requests in validate mode" } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { throw "Should not extract archive in validate mode" } -ModuleName Microsoft.AVS.Management
            Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
            Mock Get-EsxCli { throw "Should not call ESXCLI in validate mode" } -ModuleName Microsoft.AVS.Management

            $badUrl = ConvertTo-TestSecureString "not-a-valid-url"

            { Set-ToolsRepo -ToolsURL $badUrl -Validate } | Should -Not -Throw

            Should -Invoke Invoke-WebRequest -Times 0 -ModuleName Microsoft.AVS.Management
            Should -Invoke Expand-Archive -Times 0 -ModuleName Microsoft.AVS.Management
            Should -Invoke Copy-DatastoreItem -Times 2 -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Item -like "*metadata.json"
            }
            Should -Invoke Get-EsxCli -Times 0 -ModuleName Microsoft.AVS.Management
        }
    }

    Context "URL Pattern Validation" {
        It "Should throw for non-HTTP/HTTPS URL" {
            $secureUrl = ConvertTo-TestSecureString "ftp://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should throw for URL without protocol" {
            $secureUrl = ConvertTo-TestSecureString "example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should throw for file:// URL" {
            $secureUrl = ConvertTo-TestSecureString "file:///path/to/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should proceed past URL validation for valid HTTP URL" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { throw "DNS resolution failed for example.com" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "http://example.com/tools.zip"

            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*DNS resolution failed for example.com*"

            Should -Invoke Invoke-WebRequest -Times 1 -ModuleName Microsoft.AVS.Management
        }

        It "Should proceed past URL validation for valid HTTPS URL" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { throw "TLS handshake failed while connecting to https://example.com/tools.zip" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*TLS handshake failed while connecting to https://example.com/tools.zip*"

            Should -Invoke Invoke-WebRequest -Times 1 -ModuleName Microsoft.AVS.Management
        }

        It "Should proceed past URL validation for HTTPS URL with query parameters" {
            Mock Get-Datastore { @([PSCustomObject]@{ Name = "vsanDatastore"; extensionData = @{ Summary = @{ Type = 'vsan' } } }) } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { throw "403 Forbidden: SAS token expired" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://storage.example.com/tools.zip?token=secret123&sig=abc"

            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*403 Forbidden: SAS token expired*"

            Should -Invoke Invoke-WebRequest -Times 1 -ModuleName Microsoft.AVS.Management
        }
    }

    Context "URL Accessibility Validation" {
        # Tests 404 download failure (HEAD succeeds, GET fails)
        It "Should throw when file at URL returns 404" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { throw "404 Not Found" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            $secureUrl = ConvertTo-TestSecureString "https://example.com/nonexistent.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to download tools file*"

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' } -Times 1
            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile } -Times 1
        }

        # Tests 403 download failure (HEAD succeeds, GET fails)
        It "Should throw when URL returns non-200 status code" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest {
                throw "URL returned status code: 403"
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            $secureUrl = ConvertTo-TestSecureString "https://example.com/forbidden.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*URL returned status code: 403*"

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' } -Times 1
            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile } -Times 1
        }
    }

    Context "File Download Validation" {
        It "Should throw when download fails" {
            # Mock successful HEAD request
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            # Mock download/file preconditions
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { throw "Download failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to download tools file*"

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' } -Times 1
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 0
        }

        It "Should throw when downloaded file is empty" {
            # Mock successful HEAD request
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            # Mock download/file preconditions
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Get-Item { [PSCustomObject]@{ Length = 0 } } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Downloaded file is empty*"

            Should -Invoke Get-Item -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 0
        }
    }

    Context "Archive Extraction Validation" {
        It "Should throw when archive extraction fails" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem { $null } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { throw "Invalid archive" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to extract tools archive*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 0
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 0
        }
    }

    Context "VMtools Directory Validation" {
        It "Should throw when windows64 directory not found in archive" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Test-Path {
                param($Path)
                if ($Path -like '*windows64') {
                    return $false
                }
                return $true
            } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem { @() } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*windows64 directory not found*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 0
        }

        It "Should throw when windows64 metadata.json is missing" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Test-Path {
                param($Path)
                if ($Path -like '*windows64/metadata.json' -or $Path -like '*windows64\metadata.json') {
                    return $false
                }
                return $true
            } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem { @() } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*metadata.json not found in windows64 directory*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 0
        }

        It "Should throw when vmtools metadata.json is missing" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                if ($Directory -and $Path -like '*windows64*') {
                    return [PSCustomObject]@{
                        Name     = "vmtools-12.4.0"
                        FullName = "$Path/vmtools-12.4.0"
                    }
                }
                return $null
            } -ModuleName Microsoft.AVS.Management
            Mock Test-Path {
                param($Path)
                if ($Path -like '*vmtools-12.4.0/metadata.json' -or $Path -like '*vmtools-12.4.0\metadata.json') {
                    return $false
                }
                return $true
            } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*metadata.json not found inside vmtools folder*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 1
        }

        It "Should throw when vmtools directory not found in archive" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                $null
            } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*No vmtools folder found inside windows64*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 1
        }
    }

    Context "vSAN Datastore Validation" {
        It "Should throw when no vSAN datastores found" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{
                    Name = "vmtools-12.3.0"
                    FullName = "$TestDrive/vmware/apps/vmtools/windows64/vmtools-12.3.0"
                }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore { @() } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*No vSAN datastores found*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-Datastore -ModuleName Microsoft.AVS.Management -Times 1
        }

        It "Should throw when Get-Datastore fails" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{
                    Name = "vmtools-12.3.0"
                    FullName = "$TestDrive/vmware/apps/vmtools/windows64/vmtools-12.3.0"
                }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore { throw "Connection error" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to retrieve vSAN datastores*"

            Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-ChildItem -ModuleName Microsoft.AVS.Management -Times 1
            Should -Invoke Get-Datastore -ModuleName Microsoft.AVS.Management -Times 1
        }
    }

    Context "SecureString Handling" {
        It "Should pass converted SecureString URL to HEAD request" {
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest {
                throw "Stop here for test"
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Uri -eq $testUrl -and $Method -eq 'Head'
            }

            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 0
        }

        It "Should pass converted SecureString URL to download request" {
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock Invoke-WebRequest { throw "Stop here" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Uri -eq $testUrl -and $OutFile
            }

            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -Times 0
        }
    }

    Context "Version and metadata decision logic (mock-only)" {
        if (-not (Get-Module Microsoft.AVS.Management)) {
            Import-Module (Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1") -Force
        }

        InModuleScope 'Microsoft.AVS.Management' {
            BeforeAll {
                $script:originalTemp = $env:TEMP
                $script:originalTmp = $env:TMP
                $script:testTempDir = Join-Path $TestDrive 'temp'
                New-Item -Path $script:testTempDir -ItemType Directory -Force | Out-Null
                $env:TEMP = $script:testTempDir
                $env:TMP = $script:testTempDir

                function ConvertTo-TestSecureString {
                    param([string]$PlainText)
                    return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
                }

                # Shadow the real Get-EsxCli cmdlet with a plain function so Pester
                # can mock it without PowerCLI's VMHost[] type constraint blocking.
                function Get-EsxCli { param([switch]$V2, $VMHost) }

                function Initialize-SetToolsRepoScenarioMocks {
                    param(
                        [Parameter(Mandatory = $true)][string]$ToolsShortVersion,
                        [Parameter(Mandatory = $true)][string]$HighestExistingVersion,
                        [Parameter(Mandatory = $true)][bool]$VersionAlreadyExists
                    )

                    $script:toolsVersion = "vmtools-$ToolsShortVersion"
                    $script:tempRoot = Join-Path $TestDrive 'newtools_test'
                    $script:sourceDir = Join-Path $TestDrive "vmtools-$ToolsShortVersion"
                    $script:topLevelSourceDir = Join-Path $script:tempRoot 'vmware' 'apps' 'vmtools' 'windows64'
                    $script:destPath = "DS:/GuestStore/vmware/apps/vmtools/windows64"
                    $script:versionDestPath = "$script:destPath/$script:toolsVersion"
                    $script:highestExistingVersion = $HighestExistingVersion
                    $script:versionAlreadyExists = $VersionAlreadyExists

                    # Create fake extracted directory and metadata.json under $TestDrive
                    [System.IO.Directory]::CreateDirectory($script:sourceDir) | Out-Null
                    [System.IO.File]::WriteAllText((Join-Path $script:sourceDir 'metadata.json'), '{}')

                    # URL validation and download path are always mocked; no network access.
                    Mock Invoke-WebRequest {
                        if ($Method -eq 'Head') {
                            return [PSCustomObject]@{ StatusCode = 200 }
                        }

                        if ($OutFile) {
                            $parentPath = [System.IO.Path]::GetDirectoryName($OutFile)
                            if (-not [string]::IsNullOrEmpty($parentPath)) {
                                [System.IO.Directory]::CreateDirectory($parentPath) | Out-Null
                            }

                            [System.IO.File]::WriteAllText($OutFile, 'dummy')
                            return [PSCustomObject]@{ StatusCode = 200 }
                        }

                        return $null
                    } -ModuleName Microsoft.AVS.Management

                    Mock New-Item {
                        [PSCustomObject]@{ FullName = $Path; Name = (Split-Path -Path $Path -Leaf) }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like 'DS:/*' }

                    Mock Get-Item { [PSCustomObject]@{ Length = 4096 } } -ModuleName Microsoft.AVS.Management
                    Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
                    Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }

                    Mock Test-Path {
                        switch ($Path) {
                            "$script:tempRoot/tools.zip" { return $true }
                            $script:destPath { return $true }
                            $script:versionDestPath { return $script:versionAlreadyExists }
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

                    Mock Get-View { $script:browser } -ModuleName Microsoft.AVS.Management
                    Mock New-Object {
                        if ($TypeName -eq 'VMware.Vim.HostDatastoreBrowserSearchSpec') { return [PSCustomObject]@{ Query = @() } }
                        if ($TypeName -eq 'VMware.Vim.FolderFileQuery') { return [PSCustomObject]@{} }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter {
                        $TypeName -eq 'VMware.Vim.HostDatastoreBrowserSearchSpec' -or $TypeName -eq 'VMware.Vim.FolderFileQuery'
                    }

                    Mock Get-Datastore {
                        return @(
                            [PSCustomObject]@{
                                Name = 'vsanDatastore'
                                Id = 'Datastore-ds-123'
                                ExtensionData = [PSCustomObject]@{
                                    Browser = 'browser-1'
                                    Summary = [PSCustomObject]@{ Type = 'vsan'; Url = 'ds:///vmfs/volumes/vsanDatastore/' }
                                }
                            }
                        )
                    } -ModuleName Microsoft.AVS.Management

                    Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
                    Mock New-PSDrive { [PSCustomObject]@{ Name = 'DS' } } -ModuleName Microsoft.AVS.Management
                    Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

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
                    Add-Member -InputObject $script:setObj -MemberType ScriptMethod -Name invoke -Value { param($arguments) return $true } -Force
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
                $secureUrl = ConvertTo-TestSecureString 'https://example.com/tools.zip'

                { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Not -Throw

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64'
                }
                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 0 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*metadata.json'
                }
                Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
            }

            It "Newer version upload updates top-level metadata.json" {
                $IncomingVersion = '12.4.0'
                $ExistingVersion = '12.3.0'
                Initialize-SetToolsRepoScenarioMocks -ToolsShortVersion $IncomingVersion -HighestExistingVersion $ExistingVersion -VersionAlreadyExists $true
                $secureUrl = ConvertTo-TestSecureString 'https://example.com/tools.zip'

                { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Not -Throw

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    ($Item -like '*windows64/metadata.json' -or $Item -like '*windows64\metadata.json') -and
                    ($Destination -like '*GuestStore/vmware/apps/vmtools/windows64/metadata.json' -or $Destination -like '*GuestStore\vmware\apps\vmtools\windows64\metadata.json')
                }
                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 0 -Exactly -Scope It -ParameterFilter {
                    ($Item -like '*vmtools-12.4.0*metadata.json') -and
                    ($Destination -like '*GuestStore/vmware/apps/vmtools/windows64/metadata.json' -or $Destination -like '*GuestStore\vmware\apps\vmtools\windows64\metadata.json')
                }
                Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
            }

            It "Version already exists skips copy and overwrite" {
                $IncomingVersion = '12.4.0'
                $ExistingVersion = '12.4.0'
                Initialize-SetToolsRepoScenarioMocks -ToolsShortVersion $IncomingVersion -HighestExistingVersion $ExistingVersion -VersionAlreadyExists $true
                $secureUrl = ConvertTo-TestSecureString 'https://example.com/tools.zip'

                { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Not -Throw

                Should -Invoke Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 0 -Exactly -Scope It
                Should -Invoke Expand-Archive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke New-PSDrive -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
                Should -Invoke Get-EsxCli -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It
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

    It "AVSAttribute and AVSSecureFolder resolve from a separate module scope" {
        $classesPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Microsoft.AVS.Management' 'Classes.ps1')).Path
        $cdrPath     = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Microsoft.AVS.CDR'        'Microsoft.AVS.CDR.psd1')).Path

        # Escape single quotes in paths for embedding in a here-string
        $escapedClassesPath = $classesPath -replace "'", "''"
        $escapedCdrPath     = $cdrPath     -replace "'", "''"

        # Script runs in a fresh pwsh process: no AppDomain contamination from BeforeAll's Import-Module.
        # Step 1 – import the real CDR module.
        # Step 2 – dot-source Classes.ps1 inside CDR's module SessionState (mirrors ScriptsToProcess behavior).
        # Step 3 – verify both types are visible from a separate module's function scope.
        $script = @"
Import-Module '$escapedCdrPath' -Force

& (Get-Module Microsoft.AVS.CDR) { param(`$p) . `$p } -p '$escapedClassesPath'

`$consumerModule = New-Module -Name 'SimulatedManagement' -ScriptBlock {
    function Test-TypeVisibility {
        `$missing = @('AVSAttribute', 'AVSSecureFolder') | Where-Object { -not (`$_ -as [type]) }
        if (`$missing) { throw "Types not visible in consumer module scope: `$(`$missing -join ', ')" }
        'ok'
    }
}
Import-Module `$consumerModule -Force
& (Get-Module SimulatedManagement) { Test-TypeVisibility }
"@
        $output = pwsh -NoProfile -NonInteractive -Command $script 2>&1
        $LASTEXITCODE | Should -Be 0 -Because (
            "Add-Type registers types in the AppDomain — they must be visible from any module scope. " +
            "stderr: $($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })"
        )
        $output | Should -Contain 'ok'
    }
}
