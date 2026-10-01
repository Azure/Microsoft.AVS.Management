# RFC 2 - Require Authenticode signing for AVS Run Command packages

Overview

* [ ] Approved in principle
* [x] Details: [link][Details]
* [ ] Implementation: [opt-in CDR verification proposal][Implementation]; mandatory enforcement is separate work

  [Details]:#detailed-design
  [Implementation]:https://github.com/Azure/Microsoft.AVS.Management/pull/430

# Summary
[summary]: #summary

Make Authenticode code signing an upcoming requirement for Microsoft and third-party PowerShell packages supplied to AVS Run Command, including their resolved dependencies.

This RFC proposes the requirement and migration approach. It does **not** enable enforcement, announce an enforcement date, or change which packages are accepted today. Authors should prepare signed releases now; AVS will communicate the final trust policy, validation tooling, and transition dates before enforcement.

# Motivation
[motivation]: #motivation

Run Command packages execute with AVS-provided administrative sessions. Dependency version pinning and a trusted package repository help control what is installed, but do not by themselves establish the publisher or integrity of individual executable files.

Authenticode adds a verifiable publisher identity and detects changes to signed content. It complements dependency pinning, package review, input validation, and controlled distribution; a valid signature does not prove that code is safe or authorize a publisher to run arbitrary code in AVS.

# Detailed design
[design]: #detailed-design

## Scope of the upcoming requirement

After the announced transition, packages admitted to the enforced Run Command path must meet the following requirements:

* Sign every in-scope file in the released module, not just its entry-point script or manifest. The initial proposed file set is `.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.psc1`, `.dll`, and `.exe`, matching the formats supported by the proposed Linux verifier.
* Apply the same rule to the complete resolved dependency graph, including transitive dependencies and the exact versions selected by CDR redirect maps. A signed top-level package does not make an unsigned dependency acceptable.
* Cover Microsoft packages and vendor packages equally. `-dev` and `-preview` suffixes are not automatic exemptions when a package is submitted to an enforced AVS environment.
* Require a valid signature and certificate chain under the AVS-defined trust policy, plus an approved publisher identity. Merely having a signature block, a certificate trusted on the author's workstation, or a successful package download is insufficient.
* Reject missing, malformed, untrusted, or content-mismatched signatures before affected code is imported or executed. Force/reinstall options must not bypass verification.

This is a requirement for released artifacts submitted to AVS, not for every source-control commit or local development edit. Signing a NuGet package or an assembly with a strong name is not a substitute for Authenticode signatures on the in-scope files.

Files outside the initial set, such as JSON data, documentation, native `.so` libraries, and dynamically fetched content, are **not authenticated by these file checks**. Unsupported executable or loadable content must be reviewed and either covered by a separately approved integrity mechanism or rejected; exclusion from the verifier is not permission to execute it. The final coverage policy is an enforcement prerequisite.

## Publisher preparation

Package owners should inventory their release contents and dependencies, identify unsigned files, and arrange signed upstream dependency releases where necessary. Do not silently re-sign third-party code as if it were your own publisher's release.

The proposed production baseline is a code-signing certificate chaining to a root accepted by AVS, SHA-256 or stronger signing digests supported by the verifier, and a trusted timestamp. Test-only self-signed certificates must remain isolated from production trust. The final accepted certificate authorities, publisher enrollment process, algorithms, and timestamp policy will be published before enforcement.

Signing belongs in the controlled release process, after version stamping and all other content changes, and before packaging and publishing. Revalidate the extracted final package: encoding changes, line-ending conversion, or generated content after signing can invalidate signatures. Publish corrected signed artifacts as new package versions rather than replacing an existing version in place.

Keep signing keys in a protected signing service or equivalent controlled key store, never in the repository, package, or logs. Limit signing access to authorized release jobs and plan certificate renewal, rollover, and compromise response. Publishers are responsible for their signatures; AVS is responsible for defining and operating the verification and publisher-approval policy.

## Verification in the Linux runtime

Run Command uses a Linux container. PowerShell execution policies such as `AllSigned` are enforced only on Windows, so changing `ExecutionPolicy` cannot implement this requirement. Verification must be explicit in AVS package acquisition and loading.

The [opt-in CDR verification proposal][Implementation] adds `-AuthenticodeCheck` to the install/import entry points using OpenAuthenticode. It is preparatory tooling, not mandatory enforcement or a statement that all existing packages already comply. Its documented limitations include no revocation checking, a limited file-format set, and no claim of Windows Authenticode validation parity.

The enforcement design must:

* Validate the final resolved graph before making newly acquired packages available for use, and preflight all graph members before the first module import. Check manifests before using their dependency declarations.
* Bind imports to the verified artifact paths and preserve verified bytes through installation and execution. An existing cache entry or name/version match alone is not evidence that the selected files passed verification.
* Provision the verifier and its dependencies through the trusted AVS build/bootstrap path. Verification cannot establish trust in its own unverified bootstrap, and vendor scripts must not install verification tools or modify the runtime trust store.
* Produce actionable errors identifying the package, version, file, and failure category without exposing credentials or signing keys.
* Define certificate-chain, timestamp, revocation, and trust-store behavior on the actual Linux runtime, including restricted network access. Unavailable validation infrastructure must not silently turn checking off.

The current opt-in proposal does not settle approved-publisher enforcement or revocation policy. Those decisions and their implementation must be reviewed before claiming that mandatory enforcement satisfies this RFC.

## Rollout and compatibility

Use a staged transition rather than immediately rejecting today's unsigned packages:

1. **Announce and assess.** Publish the proposed requirement, inventory affected Microsoft and vendor releases and dependencies, and communicate the validation contract and migration guidance. Existing behavior remains unchanged.
2. **Audit ingestion and migrate.** Run package ingestion in audit mode: evaluate incoming packages and their resolved dependency graphs against the proposed Authenticode policy, flag violations, and continue ingestion without rejecting packages solely for these new signing-policy violations. Existing acceptance and security checks remain in force. Make opt-in validation available against the target Linux environment so package owners can reproduce findings, publish signed versions, and resolve dependency gaps.
3. **Enforce after notice.** Announce the effective date and affected package/runtime versions, then reject noncompliant artifacts in the enforced path before import or execution. Make signing part of package onboarding and release acceptance.

No cutoff date, minimum CDR version, or retirement date for existing unsigned releases is set by this RFC. AVS must explicitly communicate whether existing versions are revalidated, temporarily retained, or retired; neither indefinite grandfathering nor immediate withdrawal is implied. Any temporary exception must be AVS-approved, scoped to specific package versions, documented, and time-limited rather than implemented as a general bypass.

### Ingestion audit findings and enforcement readiness

Audit mode must surface actionable warnings in ingestion results and retain findings identifying the submitted package/version, the affected dependency/version and file, and the violated rule or verification failure category. Route findings to the package owner and AVS maintainers for remediation, and summarize affected packages and recurring violations to track migration progress. Do not report a verifier error, unavailable trust service, or unsupported check as a clean audit; distinguish incomplete validation from confirmed policy violations.

Audit mode changes the disposition of Authenticode findings, not the intended checks: use the same verification rules planned for enforcement wherever implemented, and explicitly report policy or tooling gaps. Audit findings are non-blocking during this phase, not permanent exemptions or proof that a package is trusted.

Before switching ingestion to enforcement, AVS must review audit coverage and outstanding findings, confirm that owners have received actionable reports, and ensure that affected package versions are compliant or have explicit, time-limited exceptions. Resolve the trust/timestamp policy, unsupported-content coverage, diagnostics, and treatment of existing deployed versions, then communicate the enforcement date. Audit data informs that decision; it does not automatically enable enforcement.

Before enforcement, demonstrate in the target Linux container that valid signed graphs succeed and that unsigned dependencies, modified files, untrusted chains, unapproved publishers, and unsupported executable content cannot reach execution. Include timestamp/expiry behavior, the agreed revocation and offline policy, cache reuse, certificate rollover, and verification failures before the first import in acceptance coverage.

Also demonstrate that ingestion audit mode flags those violations without blocking solely on the new Authenticode policy, preserves existing rejection checks, and records verifier failures as incomplete validation rather than success.

# Drawbacks
[drawbacks]: #drawbacks

* Publishers need certificate and signing infrastructure, secure key management, and release-process changes.
* Unsigned upstream dependencies can block migration even when the vendor's own module is signed.
* Verification adds processing cost and trust-policy operations; certificate expiry, rollover, or unavailable validation services can affect availability.
* Linux verifier coverage differs from Windows. Authenticode alone does not protect all package content or prevent signed malicious code.

# Alternatives
[alternatives]: #alternatives

* **Keep signing optional.** Minimizes disruption but leaves publisher and file-integrity checks inconsistent across packages.
* **Rely only on repository trust, pinned versions, or hashes.** Useful complementary controls, but they do not provide the same certificate-based publisher identity for individual files.
* **Require only package-level signing or provenance attestations.** Can cover a broader artifact boundary, but needs a separate verification and trust contract and does not replace the proposed per-file Authenticode requirement.
* **Use `AllSigned` alone.** Not viable for enforcement in the Linux Run Command runtime.

# Unresolved questions
[unresolved]: #unresolved-questions

* Which certificate authorities and publisher identities will AVS accept, and how will publisher enrollment, renewal, and emergency removal work?
* What exact timestamp, certificate-expiry, revocation, and offline-validation semantics can the Linux verifier support, and which are required before enforcement?
* How will unsupported file formats and loadable content be authenticated or prohibited, including content outside the resolved module tree?
* What notice period, runtime/package version boundary, and treatment of existing unsigned releases will apply?
* Which unsigned upstream dependencies need remediation, who owns that work, and what narrowly scoped exception process is necessary during migration?

## References

* [AVS scripting and packaging guidelines](../docs/README.md)
* [RFC 1 - Transition to Azure Linux 3.0](RFC-azure-linux.md)
* [CDR opt-in Authenticode verification proposal][Implementation]
* [PowerShell about_Signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.6)
* [PowerShell about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.6)
