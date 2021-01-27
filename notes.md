
https://admf.one/

Prerequisites:
 * Windows Server 2019
 * Windows PowerShell 5.1
 * ActiveDirectory PowerShell module

```powershell
Install-Module -Name ADMF -Scope AllUsers
```

https://www.windowscrush.com/promote-windows-server-2019-to-domain-controller.html

https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/

https://social.technet.microsoft.com/wiki/contents/articles/52765.windows-server-2019-step-by-step-setup-active-directory-environment-using-powershell.aspx

https://blog.netspi.com/powershell-remoting-cheatsheet/

Enable WinRM PSRemoting:

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:localhost\Client\TrustedHosts -Value *
Invoke-Command -ComputerName localhost -ScriptBlock { Hostname }
```

Check the following:
 * Rename computer to final DC name
 * Configure a static IP for the DC

```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Test-ADDSForestInstallation -DomainName now-it.works -InstallDns
Install-ADDSForest -DomainName now-it.works -InstallDns
```

```powershell
Get-Service ADWS,kdc,netlogon,dns
Set-Service ADWS -StartupType Automatic
Start-Service ADWS
```

```powershell
git clone https://github.com/awakecoding/admf-sample.git
Set-Location 'admf-sample'
New-AdmfContextStore -Name sample -Path $(Join-Path $(Get-Location) 'Contexts') -Scope SystemDefault
```

```powershell
Set-AdmfContext -Server contoso.com -Context Basic
Test-AdmfDomain -Server contoso.com
Invoke-AdmfDomain -Server contoso.com
```

```powershell
Get-ADuser -Searchbase 'DC=contoso,DC=com' -Properties Description -Filter * | Select-PSFObject @(
>>   'SamAccountName'
>>   'GivenName'
>>   'Surname'
>>   'Description To string'
>>   'UserPrincipalName'
>>   @{ Name = 'Path'; Expression = { $_.DistinguishedName -replace 'DC=.+$','%DomainDN%' -replace '^.+?,' }}
>> ) | ConvertTo-Json
```

```powershell
Set-ADAccountPassword -Identity bowens -NewPassword (ConvertTo-SecureString -AsPlainText "Password123!" -Force)
```