# Bare Metal Deployment (winrm/simple)

## Synopsis

This is an example for deploying a simple lab environment from scratch.

> Prerequisites

+ Simple Baremetal Windows Server, nothing installed, not domain-joined, reachable through WinRM

## Installation

To prepare the demo, use the three setup scripts contained in this folder:

> 01-install-prerequisites.ps1

This will install the ADMF on your client, in preparation for the Domain deployment

> 02-setup-domaincontroller.ps1

This will install the new domaincontroller (and domain/forest).
To run this script you will need to specify the computername and password of the target machine described in the prerequisites.

Examples:

```powershell
# Install to VM hosted on local Hyper-V
.\02-setup-domaincontroller.ps1 -VMName LabDC

# Install on VM available through network
.\02-setup-domaincontroller.ps1 -ComputerName labdc
```

For connecting via network to a computer identified by IP address you may need to modify your trusted hosts list.

> 03-prepare-Admf.ps1

This will prepare the target DC to run the Active Directory Management Framework.

In order to successfully run this you need to have downloaded the "Contexts" folder in the same folder as this documentation.
This guide assumes you have downloaded all together and left the structure intact.

To finish the ADMF preparations, run this:

```powershell
# Prepare VM hosted on local Hyper-V
.\03-prepare-Admf.ps1 -VMName LabDC

# Prepare VM available through network
.\03-prepare-Admf.ps1 -ComputerName labdc
```

## Execute

To execute the ADMF, log onto the previously prepared machine and start a PowerShell console:

```powershell
# Test run: See what would change
Test-AdmfDomain -Server contoso.com

# Make it happen:
Invoke-AdmfDomain -Server contoso.com
```
