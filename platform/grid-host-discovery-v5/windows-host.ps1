# Read-only future query: no service, registry, firewall, SDK, or environment setting changes.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$errors=@()
$os=$null
$kits=$null
try {
 $rows=@(Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber,ProductType,OSArchitecture)
 if($rows.Count -ne 1){throw 'No unique Windows OS identity'}
 $row=$rows[0]
 $os=[ordered]@{caption=$row.Caption;version=$row.Version;buildNumber=$row.BuildNumber;productType=[int]$row.ProductType;architecture=$row.OSArchitecture}
}catch{$errors+='OS_METADATA_UNAVAILABLE: '+$_.Exception.Message}
try {
 $root=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -Name KitsRoot10
 if(-not $root.KitsRoot10){throw 'Windows SDK installation root missing'}
 $kits=$root.KitsRoot10
}catch{$errors+='WINDOWS_SDK_ROOT_UNAVAILABLE: '+$_.Exception.Message}
[ordered]@{schemaVersion=1;os=$os;kitsRoot10=$kits;errors=$errors;windows11Qualified=$false;settingsChanged=$false} | ConvertTo-Json -Depth 8
