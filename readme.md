
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

Install PowerShell 7 (optional):

```powershell
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
```

Enable SSH server (optional):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

Enable PowerShell Remoting over SSH (optional):

```powershell
Install-Module -Name Microsoft.PowerShell.RemotingTools
Enable-SSHRemoting
Restart-Service sshd
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

Create the forest and promote the machine to domain controller. Pay careful attention to chosen DNS and NetBios domain names, because there is no going back from this point. [Best practices](https://www.varonis.com/blog/active-directory-domain-naming-best-practices/) recommend using the "ad" or "corp" subdomain of a domain under your control to avoid conflicts with public DNS records.

For instance, if you own "contoso.com", then the recommended DNS domain name should be "ad.contoso.com" instead of "contoso.local" or "contoso.loc". If you do not own a domain name, simply use and unassigned TLD such as ".loc" and it should work just fine for now.

As for the NetBios domain name, is it the one that appears in the old "DOMAIN\username" format. If you don't specify it explicitly, the "ad" subdomain will be used, which is probably not desirable. In most cases, the NetBios domain name is simply the organization name, like "CONTOSO". There are many naming restrictions, but the [most important to remember is the maximum of 15 characters](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou#netbios-domain-names).

Select the context non-interactively using `-NoDomain` because the domain does not exist yet:

```powershell
Set-AdmfContext -Server $Env:ComputerName -Context 'Basic' -NoDomain
```

Set the $UserDnsDomain and $UserDomain variables (don't copy/paste them!) with the appropriate values for your domain, then run the `Install-DCRootDomain` command to create the domain forest and promote the machine to a domain controller:

```powershell
$UserDnsDomain = 'ad.contoso.com'
$UserDomain = 'CONTOSO'
Install-DCRootDomain -DnsName $UserDnsDomain -NetBiosName $UserDomain
```

In the interactive prompt, select "Basic", then click OK. The machine will restart once the operation is complete. The next startup can take a few minutes. If it appears stuck on "Please wait for Group Policy Client", just wait a little longer, it is normal.

## Apply domain configuration

Reconnect to the machine using the new domain administrator account.

Open PowerShell as an Administrator, then test the ADMF domain configuration:

```powershell
Set-AdmfContext -Server $UserDnsDomain -Context Basic
Test-AdmfDomain -Server $UserDnsDomain
```

Take a deep breath, then apply the domain configuration:

```powershell
Invoke-AdmfDomain -Server $UserDnsDomain

[22:23:27][Resolve-DomainController] Resolved domain controller to use. Operating against NOW-IT-DC.ad.now-it.works
[22:23:27][Invoke-AdmfDomain] Performing updates to OrganizationalUnits - Create & Modify against NOW-IT-DC.ad.now-it.works
[22:23:28][Invoke-AdmfDomain] Performing updates to Groups against NOW-IT-DC.ad.now-it.works
[22:23:28][Invoke-AdmfDomain] Performing updates to Users against NOW-IT-DC.ad.now-it.works
[22:23:31][Invoke-AdmfDomain] Skipping updates to ServiceAccounts as there is no configuration data available
[22:23:31][Invoke-AdmfDomain] Performing updates to GroupMembership against NOW-IT-DC.ad.now-it.works
[22:23:32][Invoke-AdmfDomain] Skipping updates to PasswordPolicies as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Skipping updates to GroupPolicies - Create & Modify as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Skipping updates to GroupPolicyPermissions as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Skipping updates to GroupPolicyLinks - Create, Update & Disable unwanted Links as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Skipping updates to GroupPolicies - Delete as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Skipping updates to GroupPolicyLinks - Delete unwanted Links as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Performing updates to OrganizationalUnits - Delete against NOW-IT-DC.ad.now-it.works
[22:23:32][Invoke-AdmfDomain] Skipping updates to Objects as there is no configuration data available
[22:23:32][Invoke-AdmfDomain] Skipping updates to Acls as there is no configuration data available
```

## Set user passwords

References:
 * [Password must meet complexity requirements](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements)

Generate random test passwords for all users and export them to AccountPasswords.json (unsafe):

```powershell
function New-RandomPassword
{
    param(
        [Parameter(Position=0)]
        [int] $Length = 16
    )

    $charsets = @("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789")

    $sb = [System.Text.StringBuilder]::new()
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

    $bytes = New-Object Byte[] 4

    0 .. ($Length - 1) | % {
        $charset = $charsets[$_ % $charsets.Count]
        $rng.GetBytes($bytes)
        $num = [System.BitConverter]::ToUInt32($bytes, 0)
        $sb.Append($charset[$num % $charset.Length]) | Out-Null
    }

    return $sb.ToString()
}

Set-AdmfContext -Server $UserDnsDomain -Context Basic

$AccountPasswords = @()
Get-DMUser | ForEach-Object {
    $AccountPasswords += [PSCustomObject]@{
        Identity = $_.SamAccountName
        Password = $(New-RandomPassword 16)
    }
}

Set-Content -Path "AccountPasswords.json" -Value $($AccountPasswords | ConvertTo-Json) -Force
```

Import and apply the account passwords to Active Directory users:

```powershell
$AccountPasswords = $(Get-Content -Path "AccountPasswords.json") | ConvertFrom-Json
$AccountPasswords | ForEach-Object {
    $Identity = $_.Identity
    $Password = $(ConvertTo-SecureString -AsPlainText $_.Password -Force)
    Write-Host "Setting password for $Identity"
    try {
        Set-ADAccountPassword -Identity $Identity -NewPassword $Password -Reset
    } catch [Exception] {
        echo $_.Exception.GetType().FullName, $_.Exception.Message
    }
}
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
PS > Test-ADCredentials -Domain $UserDnsDomain -Username 'dford' -Password 'Password123!'
True
PS > Test-ADCredentials -Domain $UserDnsDomain -Username 'dford' -Password 'Invalid123!'
False
```

## Configure LDAPS

### Using a Self-signed Certificate

A self-signed certificate is the quickest way to get started if you can afford to ignore certificate validation. It possible to force validation of the self-signed certificate by installing it in the trusted Root CAs of the client, but this is not recommended.

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

```powershell
$LdapRenew = @"
dn:
changetype: modify
add: renewServerCertificate
renewServerCertificate: 1
- 
"@

Set-Content -Path "ldap-renew.txt" -Value $LdapRenew -Force

& ldifde -i -f ldap-renew.txt
```

You can now test that the LDAPS server accepts TLS connections using OpenSSL:

```powershell
openssl s_client -connect NOW-IT-DC.ad.now-it.works:636 -showcerts
```

### Using letsencrypt / ACME certificates

Enable HTTP inbound traffic on TCP/80 in the system firewall:

```powershell
netsh advfirewall firewall add rule name="HTTP inbound" dir=in action=allow protocol=TCP localport=80
```

Check to see if TCP/80 is already used by another program:

```powershell
netstat -an | findstr :80
```

Unless you installed IIS on your domain controller (definitely not recommended), then you shouldn't see a line showing port 80 in the LISTENING state. The goal is to respond to the ACME HTTP challenge from the domain controller to obtain trusted certificates from [letsencrypt](https://letsencrypt.org/). This challenge has to be done over TCP/80, the standard port for HTTP, since custom ports are not allowed.

Install the [Posh-ACME](https://github.com/rmbolger/Posh-ACME) PowerShell module:

```powershell
Install-Module -Name Posh-ACME -Scope AllUsers
```

Request a new certificate using a temporary web server:

```powershell
New-PACertificate 'NOW-IT-DC.ad.now-it.works' -Plugin WebSelfHost -AcceptTOS
```

Find the path to the certificate files:

```powershell
$Certificate = Get-PACertificate
$CertPath = Split-Path -Path $Certificate.PfxFullChain -Parent
```

The certificate file you want to use is fullchain.pfx with 'poshacme' as the default password if you didn't specify one. Posh-ACME exports the certificate in various file formats (PEM, PFX, etc) so feel free to look at the output files to get a better understanding. Import the new certificate into the certificate store of the local machine, then copy it from there to the Active Directory certificate store:

```powershell
$CertificatePassword = $(ConvertTo-SecureString -AsPlainText 'poshacme' -Force)
$ImportedCertificate = Import-PfxCertificate -FilePath $Certificate.PfxFullChain -CertStoreLocation 'cert:\LocalMachine\My' -Password $CertificatePassword
$Thumbprint = $ImportedCertificate.Thumbprint
$LocalCertStore = 'HKLM:/Software/Microsoft/SystemCertificates/My/Certificates'
$NtdsCertStore = 'HKLM:/Software/Microsoft/Cryptography/Services/NTDS/SystemCertificates/My/Certificates'
Copy-Item -Path "$LocalCertStore/$Thumbprint" -Destination $NtdsCertStore
```

### Using Active Directory Certificate Services (AD CS):

References:
 * [Guide to setup LDAPS on Windows Server](https://www.miniorange.com/guide-to-setup-ldaps-on-windows-server)
 * [How to set up secure LDAP for Active Directory](https://astrix.co.uk/news/2020/1/31/how-to-set-up-secure-ldap-for-active-directory#ADCS)
 * [Enable LDAP over SSL with a third-party certification authority](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority)
 * [Troubleshoot LDAP over SSL connection problems](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/ldap-over-ssl-connection-issues)
 * [Confirming a Domain Controller has a working LDAPS configuration](https://osirium.com/how-to/confirm-a-domain-controller-has-ldaps-enabled)
 * [Verify LDAP over SSL/TLS (LDAPS) and CA Certificate Using Ldp.exe](https://www.cisco.com/c/en/us/support/docs/security/firesight-management-center/118761-technote-firesight-00.html)

```powershell
Install-WindowsFeature -Name AD-Certificate
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force
```

Restart the domain controller to apply the changes.

### Disable LDAP Unauthenticated Bind

Surprisingly enough, [Active Directory still allows LDAP unauthenticated binds by default](https://blog.lithnet.io/2018/12/disabling-unauthenticated-binds-in.html) in Windows Server 2019. This means that an LDAP bind with an invalid password will fail, but an LDAP bind with an empty password will work. You probably want to disable it, especially if the domain controller is exposed on the internet for testing:

```powershell
$RootDSE = Get-ADRootDSE
$ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1' }
```

The change should be applied immediately, and future LDAP bind requests with an empty password will be denied.
