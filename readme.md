
# ADMF sample getting started guide

[Active Directory Management Framework](https://admf.one/)

This guide assumes a fresh Windows Server 2019 virtual machine as a starting point, starting from scratch. The goal is to create an isolated domain controller with a few users and groups, along with test passwords using ADMF. Everything is done locally with no PowerShell remoting involved to keep it small and simple.

## Install prerequisites

Open PowerShell as an Administrator:

Update PowerShellGet (fresh installation only):

```powershell
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force
```

Install chocolatey (optional):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

Install git (optional):

```powershell
choco install --yes git
```

Install ADMF PowerShell module:

```powershell
Install-Module -Name ADMF -Scope AllUsers -Force
```

## Import sample configuration

Clone or copy 'admf-sample' directory and change directory:

```powershell
git clone https://github.com/awakecoding/admf-sample.git
Set-Location 'admf-sample'
```

Register the 'Contexts' subdirectory as the ADMF context store named "sample":

```powershell
New-AdmfContextStore -Name sample -Path $(Join-Path $(Get-Location) 'Contexts') -Scope SystemDefault
Get-AdmfContextStore sample

Name   PathExists Path
----   ---------- ----
sample True       C:\Users\wayk-admin\admf-sample\Contexts
```

## Promote to domain controller

Before promoting the machine to domain controller, review the following:
 * The machine is configured with a static IP address
 * The machine name is final (can't be changed after)

Install Active Directory Domain Services with the management tools:

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

Make sure that the Active Directory Web Services (ADWS) service is enabled and started:

```powershell
Set-Service ADWS -StartupType Automatic
Start-Service ADWS
```

Attempt selecting the context non-interactively (doesn't work yet):

```powershell
Set-AdmfContext -Server $Env:ComputerName -Context Basic -DefineOnly
```

Create the forest 'contoso.com' and promote the machine to domain controller:

```powershell
Install-DCRootDomain -DnsName contoso.com
```

In the interactive prompt, select "Basic", then click OK. The machine will restart once the operation is complete. The next startup can take a few minutes. If it appears stuck on "Please wait for Group Policy Client", just wait a little longer, it is normal.

## Apply domain configuration

Open PowerShell as an Administrator, then test the ADMF domain configuration:

```powershell
Set-AdmfContext -Server contoso.com -Context Basic
Test-AdmfDomain -Server contoso.com
```

Take a deep breath, then apply the domain configuration:

```powershell
Invoke-AdmfDomain -Server contoso.com

[21:52:56][Resolve-DomainController] Resolved domain controller to use. Operating against NOW-IT-DC.contoso.com
[21:52:56][Invoke-AdmfDomain] Performing updates to OrganizationalUnits - Create & Modify against NOW-IT-DC.contoso.com
[21:52:56][Invoke-AdmfDomain] Performing updates to Groups against NOW-IT-DC.contoso.com
[21:52:57][Invoke-AdmfDomain] Performing updates to Users against NOW-IT-DC.contoso.com
[21:52:58][Invoke-AdmfDomain] Skipping updates to ServiceAccounts as there is no configuration data available
[21:52:58][Invoke-AdmfDomain] Performing updates to GroupMembership against NOW-IT-DC.contoso.com
[21:52:59][Invoke-AdmfDomain] Skipping updates to PasswordPolicies as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Skipping updates to GroupPolicies - Create & Modify as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Skipping updates to GroupPolicyPermissions as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Skipping updates to GroupPolicyLinks - Create, Update & Disable unwanted Links as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Skipping updates to GroupPolicies - Delete as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Skipping updates to GroupPolicyLinks - Delete unwanted Links as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Performing updates to OrganizationalUnits - Delete against NOW-IT-DC.contoso.com
[21:52:59][Invoke-AdmfDomain] Skipping updates to Objects as there is no configuration data available
[21:52:59][Invoke-AdmfDomain] Skipping updates to Acls as there is no configuration data available
```

## Set user passwords

You can then set a dummy/unsafe password for all users (requires improvement):

```powershell
$UnsafePassword = $(ConvertTo-SecureString -AsPlainText "Password123!" -Force)
Get-DMUser | ForEach-Object { Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $UnsafePassword }
```

The username / password can then be validated using the Test-ADCredentials helper function:

```powershell
function Test-ADCredentials {
	param($username, $password, $domain)
	Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
	$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $domain)
	$pc.ValidateCredentials($username, $password)
}
```

```powershell
PS > Test-ADCredentials -Domain 'contoso.com' -Username 'dford' -Password 'Password123!'
True
PS > Test-ADCredentials -Domain 'contoso.com' -Username 'dford' -Password 'Invalid123!'
False
```

## Configure LDAPS

Using a self-signed certificate:

```powershell
$Domain = Get-ADDomain
$DomainName = $Domain.DnsRoot
$DnsName = $Env:ComputerName, $DomainName -Join '.'
$NtdsPath = 'HKLM:/Software/Microsoft/Cryptography/Services/NTDS/SystemCertificates/My/Certificates'

$MyCert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation cert:/LocalMachine/My
$Thumbprint = $MyCert.Thumbprint

if (-Not (Test-Path $NtdsPath)) {
    New-Item $NtdsPath -Force
}

Copy-Item -Path HKLM:/Software/Microsoft/SystemCertificates/My/Certificates/$Thumbprint -Destination $NtdsPath
```

To apply the changes, you can either reboot the machine or tell the LDAP server to reload the certificate. Create a text file "ldaps-renew.txt" with the following contents:

```
dn:
changetype: modify
add: renewServerCertificate
renewServerCertificate: 1
-
```

Then call `ldifde -i -f ldaps-renew.txt`

Using Active Directory Certificate Services (AD CS):

 * [Guide to setup LDAPS on Windows Server](https://www.miniorange.com/guide-to-setup-ldaps-on-windows-server)
 * [How to set up secure LDAP for Active Directory](https://astrix.co.uk/news/2020/1/31/how-to-set-up-secure-ldap-for-active-directory#ADCS)

```powershell
Install-WindowsFeature -Name AD-Certificate
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force
```

Restart the domain controller to apply the changes.
