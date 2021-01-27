[CmdletBinding()]
param (
    [string]
    $ContextPath = "$PSScriptRoot\Contexts",

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

$workingDirectory = New-Item -Path (Get-PSFPath -Name Temp) -Name "ADMF_Example_$(Get-Random)" -ItemType Directory -Force
Save-Module ADMF -Path $workingDirectory.FullName

foreach ($folder in Get-ChildItem -Path $workingDirectory.FullName) {
    Copy-Item -Path $folder.FullName -Destination 'C:\Program Files\WindowsPowerShell\Modules\' -Recurse -Force -ToSession $session
}
Invoke-Command -Session $session {
    $null = New-Item -Path C:\Contexts -ItemType Directory -Force
}
foreach ($folder in Get-ChildItem -Path $ContextPath) {
    Copy-Item -Path $folder.FullName -Destination 'C:\Contexts' -Recurse -Force -ToSession $session
}
New-AdmfContextStore -Name Demo -Path C:\Contexts -Scope SystemDefault