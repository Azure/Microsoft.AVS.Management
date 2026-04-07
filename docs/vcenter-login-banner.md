
## 1. Objective

Enable AVS customers to configure a vCenter login banner (login message + consent checkbox) via a Run Command, without requiring manual UI access or VCSA OS-level credentials.

Regulated customers (healthcare, finance, government) need an auditable login banner on the vCenter login page to meet compliance requirements (e.g., Tenable vSphere 8.0 audit, NIST, STIG).

### What We Need From Customers

Before execution, the customer must provide:

| Input | Description | Required |
|-------|-------------|----------|
| **Banner Title** | Title shown on the vCenter login page (e.g., "Authorized Users Only") | Yes |
| **Banner Message** | Full message/terms text displayed when the user clicks the login message | Yes |
| **Enable Consent Checkbox** | Whether the user must check a consent checkbox before logging in | Yes |

---

## 2. Why Method 1 Won't Work

### Method 1: PowerCLI / API-Based (Insufficient)

The vCenter login banner has **two layers**:

| Layer | What It Controls | API Exposed? |
|-------|-----------------|--------------|
| **Layer 1 — Configuration Data** | Title, message text, consent checkbox setting | Yes — via vCenter APIs / PowerCLI (`VMware.vSphere.SsoAdmin`) |
| **Layer 2 — Activation Switch** | The "Show login message" ON/OFF toggle in the UI | **No — not exposed via any public API** |

**The problem:** With Method 1, we can configure Layer 1 (set the title, message, and consent flag), but we **cannot toggle Layer 2** (the "Show login message" switch). The vSphere Client UI ignores all Layer 1 configuration data unless Layer 2 is enabled. This means:

- Even after setting banner text via API, the banner **does not appear** on the login page.
- A customer or DRI would still need to manually go into the vSphere Client UI → Administration → SSO → Configuration → Login Message → toggle "Show login message" ON, and then re-enter the banner details.
- Many AVS customers **do not have SSO Administrator access** to perform this manual step.
- Even when they do, this defeats the purpose — it's still a manual process.

**Verification:** Using browser developer tools on the vSphere Client, the UI makes an XHR call (`logonbanner`) to save the banner configuration data (Layer 1), but **no SOAP or backend API call is triggered** for the ON/OFF toggle itself. This confirms the activation switch is handled internally by vCenter/VCSA and is not exposed to external callers.

### Method 1 Verdict: Does not fully meet the goal.

---

## 3. Method 2: VCSA Appliance Shell (Proposed Approach)

### Method 2: vCenter Appliance Shell / SSH to VCSA

VMware provides an appliance shell method that can **fully enable the login banner — both layers** (configuration data + activation switch).

However, this requires **VCSA OS-level credentials**, which AVS cannot provide directly to customers.

**Proposed solution:** A Run Command that delegates execution to the Microsoft-managed backend automation, which has approved access to the VCSA. The AVS platform already pre-establishes SSH sessions to vCenter (`$SSH_Sessions["VC"]`), so a Run Command can execute appliance shell commands to:

1. Set the banner title and message text (Layer 1)
2. Toggle "Show login message" ON (Layer 2)
3. Enable/disable the consent checkbox
4. Read current banner configuration for verification
5. Disable/remove the banner for rollback

### Why This Can Work

- AVS pre-establishes `$SSH_Sessions["VC"]` — a Lazy SSH session to the vCenter appliance, available to all Run Command scripts.
- The Run Command runs with Microsoft-managed privileges, so VCSA OS-level access is handled by the platform — customers never see or need root credentials.
- This approach fully controls both Layer 1 and Layer 2.

### Method 2 Verdict: Fully meets the goal if SSH-based Run Command execution is approved.

---

## 4. Implementation Log

| Date | Action | Details |
|------|--------|---------|
| 2026-04-06 | Research complete | No existing SSH-based run commands in codebase. `$SSH_Sessions["VC"]` available but unused. Method 1 (PowerCLI) confirmed insufficient — toggle not API-exposed. |
| 2026-04-06 | Functions implemented | Added `Set-VCLoginBanner`, `Get-VCLoginBanner`, `Remove-VCLoginBanner` to `Microsoft.AVS.Management.psm1` using Method 2 (SSH to VCSA via `$SSH_Sessions["VC"]`). Updated `FunctionsToExport` in `.psd1`. |
| | | |

---

## 5. References

- [Tenable vSphere 8.0 login banner audit](https://www.tenable.com/audits/items/VMware_vSphere_Security_Configuration_Guide_8.0.audit:d4dc37573cf054a9ca3c7bc19911fbab)
- [VMware TechDocs — Manage the login banner](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/vsphere-authentication/vsphere-authentication-with-vcenter-single-sign-on-authentication/managing-the-login-message-authentication/manage-the-login-banner-authentication.html)
- [AVS Run Command docs](https://learn.microsoft.com/en-us/azure/azure-vmware/using-run-command)

Code Changes Summary
Files Modified:

Microsoft.AVS.Management.psm1 — Added 3 new functions:
Function	Purpose	Timeout	Parameters
Set-VCLoginBanner	Sets banner title, message, consent checkbox AND enables the Layer 2 toggle	30 min	BannerTitle (string, required), BannerMessage (string, required), EnableConsent (bool, required)
Get-VCLoginBanner	Reads current banner config, returns via $NamedOutputs	10 min	None
Remove-VCLoginBanner	Disables Layer 2 toggle (rollback). Preserves config data.	10 min	None
Microsoft.AVS.Management.psd1 — Added all 3 functions to FunctionsToExport
How it works:

All 3 functions use $SSH_Sessions["VC"].Value (pre-established by AVS) to SSH into the VCSA
Commands are executed via Invoke-SSHCommand calling /opt/vmware/bin/sso-config.sh
Set-VCLoginBanner executes 3 SSH commands in sequence:
-set_logon_banner -title '...' -content '...' — sets Layer 1 (config data)
-set_logon_banner -enable_checkbox true/false — sets consent requirement
-set_logon_banner -enable true — flips Layer 2 toggle ON
All string inputs sanitized via Limit-WildcardsandCodeInjectionCharacters
Single quotes escaped in shell commands to prevent injection
Each SSH command result checked via ExitStatus — throws with context on failure
Get-VCLoginBanner returns output via Set-Variable -Name NamedOutputs -Scope Global (max 32KB structured result back to ARM)
Remove-VCLoginBanner only disables the toggle — preserves title/message for easy re-enable
AVS conventions followed:

[CmdletBinding()] + [AVSAttribute(timeout, UpdatesSDDC = $false)] on every function
Comment-based help (.SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE)
Input sanitization, ValidateNotNullOrEmpty, error messages with context
Write-Host for user-facing output, throw for failures
No Connect-VIServer / Connect-SsoAdminServer calls
Status: Implemented, pending testing on a dev VCSA to verify sso-config.sh flags.