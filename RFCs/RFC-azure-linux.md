# RFC 1 - Transition to Azure Linux 3.0

Overview

* [ ] Approved in principle
* [ ] Details: [link][Details]
* [ ] Implementation: [status/link][Implementation]

  [Details]:#detailed-design
  [Implementation]:?

# Summary
[summary]: #summary

Switch from Alpine to Azure Linux 3.0 containers hosting the Run Command PowerShell environment. To minimize churn, also switch to PowerShell 7.6 as the new LTS runtime and PSResourceGet as the recommended package manager.

# Motivation
[motivation]: #motivation

- The PowerShell team stopped releasing container images in general, and the .NET team stopped releasing Alpine PowerShell images, with the suggestion to align on Azure Linux 3.0 as the base image.
- PowerShell 7.6 will ship with the fully-featured PSResourceGet, which is required for correct and secure dependency resolution.

# Detailed design
[design]: #detailed-design

- To minimize the surface for security/CVE issues, this will use the [distroless/minimal](mcr.microsoft.com/azurelinux/distroless/minimal:3.0) distribution, which can impact current script vendors if they rely on OS tools outside of pure PowerShell cmdlets.
- For pure PowerShell dependencies, the transition should be largely transparent to PowerShell scripts.
- We'll advertise the new minimal runtime in package manifests.

# Drawbacks
[drawbacks]: #drawbacks

* Potentially breaking some scripts that step out of PowerShell for certain tools.

We can review the scripts for such occurrences and add the tools on an as-needed basis or bring up the issue to the vendor team.

# Alternatives
[alternatives]: #alternatives

* Stay on Alpine and continue to install PowerShell runtime manually.

This is fragile and can potentially stop working down the road due to internal/security requirements for service container builds.

* We still need to migrate to PowerShell 7.6 as 7.4 will be out of support.

# Unresolved questions
[unresolved]: #unresolved-questions

* ?