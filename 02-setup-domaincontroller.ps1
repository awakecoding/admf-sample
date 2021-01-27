[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Computer')]
    [string]
    $ComputerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'VMHost')]
    [string]
    $VMName,

    [pscredential]
    $Credential = (Get-Credential)
)

$parameters = $PSBoundParameters | ConvertTo-PSFHashtable -Include ComputerName, VMName
try { $session = New-PSSession @parameters -Credential $Credential -ErrorAction Stop }
catch {
    Write-Warning "Failed to connect to target host: $_"
    throw
}

# Install
Install-DCRootDomain -ComputerName $session -DnsName contoso.com
