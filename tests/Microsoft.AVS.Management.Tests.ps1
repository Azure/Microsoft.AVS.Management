BeforeAll {
    # Define the AVSAttribute class that Management module functions use
    # This is a minimal definition matching what's in Microsoft.AVS.Management/Classes.ps1
    if (-not ('AVSAttribute' -as [type])) {
        class AVSAttribute : Attribute {
            [bool]$UpdatesSDDC = $false
            [TimeSpan]$Timeout
            [bool]$AutomationOnly = $false
            AVSAttribute([int]$timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
        }
    }

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
                    FullName = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "avs-validate-test")
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
        It "Should wrap original error in descriptive message" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { throw "Permission denied" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to create temporary directory*Permission denied*"
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{
                    Name = "vmtools-$IncomingVersion"
                    FullName = "/tmp/newtools_test/vmware/apps/vmtools/windows64/vmtools-$IncomingVersion"
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test_403" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
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

    Context "Temporary Directory Creation" {
        It "Should throw when temporary directory cannot be created" {
            # Tests that temp directory creation failure is caught and wrapped
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { throw "Permission denied" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to create temporary directory*"

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' } -Times 1
        }
    }

    Context "Temp Cleanup Guard" {
        It "Should remove temp directory when cleanup path passes safety guard" {
            $tempRoot = [System.IO.Path]::GetTempPath()
            $cleanupPath = Join-Path -Path $tempRoot -ChildPath "newtools_test_cleanup"

            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock New-Item {
                [PSCustomObject]@{ FullName = $cleanupPath }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            Mock Invoke-WebRequest { throw "Download failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to download tools file*Download failed*"

            Should -Invoke Remove-Item -ModuleName Microsoft.AVS.Management -Times 1 -ParameterFilter {
                $Path -eq $cleanupPath -and $Recurse -and $Force
            }
        }

        It "Should not remove temp directory when cleanup path does not exist" {
            $tempRoot = [System.IO.Path]::GetTempPath()
            $cleanupPath = Join-Path -Path $tempRoot -ChildPath "newtools_test_cleanup_missing"

            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock New-Item {
                [PSCustomObject]@{ FullName = $cleanupPath }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            Mock Invoke-WebRequest { throw "Download failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            Mock Test-Path {
                param($Path)
                if ($Path -eq $cleanupPath) { return $false }
                return $true
            } -ModuleName Microsoft.AVS.Management
            Mock Remove-Item { } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to download tools file*Download failed*"

            Should -Invoke Remove-Item -ModuleName Microsoft.AVS.Management -Times 0
        }
    }

    Context "File Download Validation" {
        It "Should throw when download fails" {
            # Mock successful HEAD request
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            # Mock successful temp directory creation
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            # Mock file and cleanup operations
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

            # Mock successful temp directory creation
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            # Mock file and cleanup operations
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

            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test"; Name = "newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like '*newtools*' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{
                    Name = "vmtools-12.3.0"
                    FullName = "/tmp/newtools_test/vmware/apps/vmtools/windows64/vmtools-12.3.0"
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
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test"; Name = "newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like '*newtools*' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{
                    Name = "vmtools-12.3.0"
                    FullName = "/tmp/newtools_test/vmware/apps/vmtools/windows64/vmtools-12.3.0"
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

            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            Mock Invoke-WebRequest { throw "Stop here" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Uri -eq $testUrl -and $OutFile
            }

            Should -Invoke New-Item -ModuleName Microsoft.AVS.Management -Times 1
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
                        [PSCustomObject]@{ FullName = $script:tempRoot; Name = 'newtools_test' }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like '*newtools*' }

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

Describe "Set-StoragePolicyOnVM" {
    BeforeAll {
        # Use local stubs so tests are not blocked by PowerCLI type binding.
        if (-not ('VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidVmConfig' -as [type])) {
            Add-Type @"
namespace VMware.VimAutomation.ViCore.Types.V1.ErrorHandling {
    public class InvalidVmConfig : System.Exception {
        public InvalidVmConfig(string message) : base(message) {}
    }
}
"@
        }

        function global:Get-SpbmEntityConfiguration {
            param($VM)
            $null
        }

        function global:Set-VM {
            param($VM, $StoragePolicy, [switch]$Confirm, $ErrorAction)
            $null
        }
    }

    if (-not (Get-Module Microsoft.AVS.Management)) {
        Import-Module (Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1") -Force
    }

    InModuleScope 'Microsoft.AVS.Management' {
        Context "Unsupported Current Policy Check" {
            It "Should write error when VM current policy is not in supported vSAN policy list" {
                $vm = [PSCustomObject]@{ Name = 'TestVM' }
                $currentPolicy = [PSCustomObject]@{ Name = 'OldPolicy' }
                $targetPolicy = [PSCustomObject]@{ Name = 'NewPolicy' }
                $supportedPolicies = @($false)

                Mock Get-SpbmEntityConfiguration {
                    [PSCustomObject]@{ StoragePolicy = $currentPolicy }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Error { } -ModuleName Microsoft.AVS.Management
                Mock Set-VM { } -ModuleName Microsoft.AVS.Management

                Set-StoragePolicyOnVM -VM $vm -VSANStoragePolicies $supportedPolicies -StoragePolicy $targetPolicy

                Should -Invoke Write-Error -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like "*Modifying storage policy on TestVM is not supported*"
                }
            }
        }

        Context "Success Path" {
            It "Should call Set-VM and write success output when policy update succeeds" {
                $vm = [PSCustomObject]@{ Name = 'TestVM' }
                $currentPolicy = [PSCustomObject]@{ Name = 'CurrentPolicy' }
                $targetPolicy = [PSCustomObject]@{ Name = 'NewPolicy' }
                $supportedPolicies = @($true)

                Mock Get-SpbmEntityConfiguration {
                    [PSCustomObject]@{ StoragePolicy = $currentPolicy }
                } -ModuleName Microsoft.AVS.Management
                Mock Set-VM { } -ModuleName Microsoft.AVS.Management
                Mock Write-Output { } -ModuleName Microsoft.AVS.Management
                Mock Write-Error { } -ModuleName Microsoft.AVS.Management

                Set-StoragePolicyOnVM -VM $vm -VSANStoragePolicies $supportedPolicies -StoragePolicy $targetPolicy

                Should -Invoke Set-VM -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $VM.Name -eq 'TestVM' -and $StoragePolicy.Name -eq 'NewPolicy' -and $Confirm -eq $false
                }
                Should -Invoke Write-Output -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $InputObject -like "*Successfully set the storage policy on VM TestVM to NewPolicy*"
                }
                Should -Not -Invoke Write-Error -ModuleName Microsoft.AVS.Management
            }
        }

        Context "Compatibility Failure Path" {
            It "Should write compatibility error when Set-VM throws InvalidVmConfig" {
                $vm = [PSCustomObject]@{ Name = 'TestVM' }
                $currentPolicy = [PSCustomObject]@{ Name = 'CurrentPolicy' }
                $targetPolicy = [PSCustomObject]@{ Name = 'NewPolicy' }
                $supportedPolicies = @($true)
                $script:capturedWriteErrorMessage = $null

                Mock Get-SpbmEntityConfiguration {
                    [PSCustomObject]@{ StoragePolicy = $currentPolicy }
                } -ModuleName Microsoft.AVS.Management
                Mock Set-VM {
                    $exceptionArgs = @(
                        'errId',
                        [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ErrorCategory]0,
                        'Compatibility failure',
                        [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimExceptionSeverity]0,
                        $null,
                        $null,
                        $null,
                        $null,
                        $null,
                        $null,
                        $null
                    )
                    throw (New-Object 'VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidVmConfig' -ArgumentList $exceptionArgs)
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Error {
                    param($Message)
                    $script:capturedWriteErrorMessage = $Message
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Output { } -ModuleName Microsoft.AVS.Management

                Set-StoragePolicyOnVM -VM $vm -VSANStoragePolicies $supportedPolicies -StoragePolicy $targetPolicy

                $script:capturedWriteErrorMessage | Should -BeLike '*The selected storage policy NewPolicy is not compatible with TestVM*may need more hosts*Compatibility failure*'
                Should -Not -Invoke Write-Output -ModuleName Microsoft.AVS.Management
            }
        }

        Context "Generic Failure Path" {
            It "Should write generic error when Set-VM throws a normal exception" {
                $vm = [PSCustomObject]@{ Name = 'TestVM' }
                $currentPolicy = [PSCustomObject]@{ Name = 'CurrentPolicy' }
                $targetPolicy = [PSCustomObject]@{ Name = 'NewPolicy' }
                $supportedPolicies = @($true)
                $script:capturedGenericWriteErrorMessage = $null

                Mock Get-SpbmEntityConfiguration {
                    [PSCustomObject]@{ StoragePolicy = $currentPolicy }
                } -ModuleName Microsoft.AVS.Management
                Mock Set-VM {
                    throw 'Network timeout'
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Error {
                    param($Message)
                    $script:capturedGenericWriteErrorMessage = $Message
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Output { } -ModuleName Microsoft.AVS.Management

                Set-StoragePolicyOnVM -VM $vm -VSANStoragePolicies $supportedPolicies -StoragePolicy $targetPolicy

                $script:capturedGenericWriteErrorMessage | Should -BeLike '*Was not able to set the storage policy on TestVM*Network timeout*'
                Should -Not -Invoke Write-Output -ModuleName Microsoft.AVS.Management
            }
        }
    }
}

Describe "Remove-AvsUnassociatedObject" {
    BeforeAll {
        # Stub Get-VsanView — PowerCLI cmdlet not present outside a datacenter environment
        if (-not (Get-Command Get-VsanView -ErrorAction SilentlyContinue)) {
            function global:Get-VsanView { param($Id) $null }
        }
        # Always override Get-View with an untyped stub so PowerCLI's typed parameter
        # binding does not reject PSCustomObject mocks before Pester can intercept.
        function global:Get-View {
            param($VIObject, $Id, $Property, $Filter)
            $null
        }
    }

    InModuleScope 'Microsoft.AVS.Management' {
        Context "UUID Not Found" {
            It "Should write warning and not attempt deletion when UUID is absent from cluster" {
                $script:deleteWasCalled = $false

                $fakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $fakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }
                $fakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:deleteWasCalled = $true
                } -Force

                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{ Identities = @() }
                } -Force

                Mock Get-Cluster { $fakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-MgmtResourcePoolVMs { [PSCustomObject]@{ Names = @(); MoRefs = @(); Count = 0 } } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $fakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $fakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like "*aaaabbbb-cccc-dddd-eeee-ffff00001111*not found*"
                }
                $script:deleteWasCalled | Should -Be $false
            }
        }

        Context "Cluster Not Found" {
            It "Should throw when Get-Cluster cannot find the cluster" {
                Mock Get-Cluster { throw "Cluster 'BadCluster' not found." } -ModuleName Microsoft.AVS.Management

                { Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'BadCluster' } |
                    Should -Throw -ExpectedMessage "*BadCluster*"
            }
        }

        Context "Safety Check: Management Object" {
            BeforeEach {
                $script:mgmtDeleteWasCalled = $false

                $script:mgmtFakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $script:mgmtFakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }
                $script:mgmtFakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $script:mgmtFakeVsanIntSys -MemberType ScriptMethod -Name GetVsanObjExtAttrs -Value {
                    param($uuid) '{}'
                } -Force
                Add-Member -InputObject $script:mgmtFakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:mgmtDeleteWasCalled = $true
                } -Force

                Mock Get-Cluster { $script:mgmtFakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $script:mgmtFakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $script:mgmtFakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $false; IsDegraded = $false; HealthState = 'Healthy' }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management
            }

            It "Should skip and warn InMgmt=True when object name matches a management VM name" {
                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'cloud-admin-vm'
                                Owner = $null; Content = $null; Type = $null; Description = $null
                            }
                        )
                    }
                } -Force

                Mock Get-MgmtResourcePoolVMs {
                    [PSCustomObject]@{ Names = @('cloud-admin-vm'); MoRefs = @(); Count = 1 }
                } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like "*InMgmt=True*"
                }
                $script:mgmtDeleteWasCalled | Should -Be $false
            }

            It "Should skip and warn InMgmt=True when object owner MoRef matches a management VM MoRef" {
                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'orphan-object-01'
                                Owner = 'vm-9876'; Content = $null; Type = $null; Description = $null
                            }
                        )
                    }
                } -Force

                Mock Get-MgmtResourcePoolVMs {
                    [PSCustomObject]@{ Names = @(); MoRefs = @('vm-9876'); Count = 1 }
                } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like "*InMgmt=True*"
                }
                $script:mgmtDeleteWasCalled | Should -Be $false
            }
        }

        Context "Safety Check: System-Like Object" {
            It "Should skip and warn SystemLike=True when object matches exclude pattern" {
                $script:systemLikeDeleteWasCalled = $false

                $fakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $fakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }

                $fakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name GetVsanObjExtAttrs -Value {
                    param($uuid) '{}'
                } -Force
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:systemLikeDeleteWasCalled = $true
                } -Force

                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'vsan-internal-obj'
                                Owner = 'owner-1'; Content = $null; Type = $null; Description = 'normal-object'
                            }
                        )
                    }
                } -Force

                Mock Get-Cluster { $fakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-MgmtResourcePoolVMs {
                    [PSCustomObject]@{ Names = @(); MoRefs = @(); Count = 0 }
                } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $fakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $fakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $false; IsDegraded = $false; HealthState = 'Healthy' }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like '*SystemLike=True*'
                }
                $script:systemLikeDeleteWasCalled | Should -Be $false
            }
        }

        Context "Safety Check: Unhealthy Object" {
            BeforeEach {
                $script:unhealthyDeleteWasCalled = $false

                $script:unhealthyFakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $script:unhealthyFakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }

                $script:unhealthyFakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $script:unhealthyFakeVsanIntSys -MemberType ScriptMethod -Name GetVsanObjExtAttrs -Value {
                    param($uuid) '{}'
                } -Force
                Add-Member -InputObject $script:unhealthyFakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:unhealthyDeleteWasCalled = $true
                } -Force

                $script:unhealthyObjSys = New-Object psobject
                Add-Member -InputObject $script:unhealthyObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'user-data-object-01'
                                Owner = 'owner-1'; Content = $null; Type = $null; Description = 'payload'
                            }
                        )
                    }
                } -Force

                Mock Get-Cluster { $script:unhealthyFakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-MgmtResourcePoolVMs {
                    [PSCustomObject]@{ Names = @(); MoRefs = @(); Count = 0 }
                } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $script:unhealthyFakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $script:unhealthyFakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $script:unhealthyObjSys } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management
            }

            It "Should skip and warn when object health is Absent" {
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $true; IsDegraded = $false; HealthState = 'Absent' }
                } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like '*Health=Absent*'
                }
                $script:unhealthyDeleteWasCalled | Should -Be $false
            }

            It "Should skip and warn when object health is Degraded" {
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $false; IsDegraded = $true; HealthState = 'Degraded' }
                } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -ParameterFilter {
                    $Message -like '*Health=Degraded*'
                }
                $script:unhealthyDeleteWasCalled | Should -Be $false
            }
        }

        Context "Happy Path (Successful Deletion)" {
            It "Should delete object and write success output when all safety checks pass" {
                $script:happyPathDeleteCallCount = 0

                $fakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $fakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }

                $fakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name GetVsanObjExtAttrs -Value {
                    param($uuid) '{}'
                } -Force
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:happyPathDeleteCallCount += 1
                } -Force

                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'user-data-object-01'
                                Owner = 'owner-1'; Content = $null; Type = $null; Description = 'payload'
                            }
                        )
                    }
                } -Force

                Mock Get-Cluster { $fakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-MgmtResourcePoolVMs { [PSCustomObject]@{ Names = @(); MoRefs = @(); Count = 0 } } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $fakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $fakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $false; IsDegraded = $false; HealthState = 'Healthy' }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Host { } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster'

                $script:happyPathDeleteCallCount | Should -Be 1
                Should -Invoke Write-Host -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $Object -like '*Deleted aaaabbbb-cccc-dddd-eeee-ffff00001111*'
                }
                Should -Not -Invoke Write-Warning -ModuleName Microsoft.AVS.Management
            }
        }

        Context "Deletion Failure Handling" {
            It "Should warn and continue when DeleteVsanObjects throws" {
                $script:deleteFailureCallCount = 0

                $fakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $fakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }

                $fakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name GetVsanObjExtAttrs -Value {
                    param($uuid) '{}'
                } -Force
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:deleteFailureCallCount += 1
                    throw 'delete api failed'
                } -Force

                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'user-data-object-01'
                                Owner = 'owner-1'; Content = $null; Type = $null; Description = 'payload'
                            }
                        )
                    }
                } -Force

                Mock Get-Cluster { $fakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-MgmtResourcePoolVMs { [PSCustomObject]@{ Names = @(); MoRefs = @(); Count = 0 } } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $fakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $fakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $false; IsDegraded = $false; HealthState = 'Healthy' }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                { Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster' } | Should -Not -Throw

                $script:deleteFailureCallCount | Should -Be 1
                Should -Invoke Write-Warning -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $Message -like '*Failed to delete aaaabbbb-cccc-dddd-eeee-ffff00001111*delete api failed*'
                }
            }
        }

        Context "Extended Attributes Parse Failure" {
            It "Should continue safety checks and delete when ext JSON parsing fails" {
                $script:extParseDeleteCallCount = 0

                $fakeCluster = [PSCustomObject]@{
                    Name = 'TestCluster'
                    ExtensionData = [PSCustomObject]@{
                        MoRef = [PSCustomObject]@{ Type = 'ClusterComputeResource'; Value = 'domain-c1' }
                    }
                }
                $fakeHost = [PSCustomObject]@{
                    ConnectionState = 'Connected'
                    ExtensionData = [PSCustomObject]@{
                        ConfigManager = [PSCustomObject]@{
                            VsanInternalSystem = [PSCustomObject]@{ Type = 'HostVsanInternalSystem'; Value = 'vsanIntSys-1' }
                        }
                    }
                }

                $fakeVsanIntSys = New-Object psobject
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name GetVsanObjExtAttrs -Value {
                    param($uuid) 'not-json'
                } -Force
                Add-Member -InputObject $fakeVsanIntSys -MemberType ScriptMethod -Name DeleteVsanObjects -Value {
                    param($uuids, $force)
                    $script:extParseDeleteCallCount += 1
                } -Force

                $fakeObjSys = New-Object psobject
                Add-Member -InputObject $fakeObjSys -MemberType ScriptMethod -Name VsanQueryObjectIdentities -Value {
                    param($clusterMo, $a, $b, $c, $d, $e)
                    [PSCustomObject]@{
                        Identities = @(
                            [PSCustomObject]@{
                                Uuid = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
                                Name = 'user-data-object-01'
                                Owner = 'owner-1'; Content = $null; Type = $null; Description = 'payload'
                            }
                        )
                    }
                } -Force

                Mock Get-Cluster { $fakeCluster } -ModuleName Microsoft.AVS.Management
                Mock Get-MgmtResourcePoolVMs { [PSCustomObject]@{ Names = @(); MoRefs = @(); Count = 0 } } -ModuleName Microsoft.AVS.Management
                Mock Get-VMHost { $fakeHost } -ModuleName Microsoft.AVS.Management
                Mock Get-View { $fakeVsanIntSys } -ModuleName Microsoft.AVS.Management
                Mock Get-VsanView { $fakeObjSys } -ModuleName Microsoft.AVS.Management
                Mock Get-HealthFromExt {
                    [PSCustomObject]@{ IsAbsent = $false; IsDegraded = $false; HealthState = 'Healthy' }
                } -ModuleName Microsoft.AVS.Management
                Mock Write-Host { } -ModuleName Microsoft.AVS.Management
                Mock Write-Warning { } -ModuleName Microsoft.AVS.Management

                { Remove-AvsUnassociatedObject -Uuid 'aaaabbbb-cccc-dddd-eeee-ffff00001111' -ClusterName 'TestCluster' } | Should -Not -Throw

                $script:extParseDeleteCallCount | Should -Be 1
                Should -Invoke Get-HealthFromExt -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -ParameterFilter {
                    $null -eq $Ext
                }
                Should -Not -Invoke Write-Warning -ModuleName Microsoft.AVS.Management
            }
        }
    }
}
