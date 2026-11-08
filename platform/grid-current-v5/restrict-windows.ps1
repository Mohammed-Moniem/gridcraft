# Staged only. Requires separate admission for temporary per-program firewall rules.
param(
 [Parameter(Mandatory=$true)][string]$NodePath,
 [Parameter(Mandatory=$true)][string]$KitPath,
 [Parameter(Mandatory=$true)][string]$Workspace,
 [Parameter(Mandatory=$true)][string]$AdmissionPath,
 [Parameter(Mandatory=$true)][string]$AdmissionSha256,
 [Parameter(Mandatory=$true)][ValidateSet('native','gui','browser','public')][string]$Stage
)
$ErrorActionPreference='Stop'
$ownedRules=@()
$removed=@()
$primaryError=$null
$cleanupErrors=[System.Collections.Generic.List[string]]::new()
$prefix='GridCurrentQualification-'+[Guid]::NewGuid().ToString('N')
$proofPath=Join-Path $Workspace "qualification/$Stage/WINDOWS-NETWORK.json"
$proof=[ordered]@{schemaVersion=1;passed=$false;stage=$Stage;programs=@();positiveControlConnected=$false;nodeDirectIpDenied=$false;cleanupVerified=$false;ruleScope='Explicit admitted executable paths only; not arbitrary descendants or OS-wide isolation';windows11Qualified=$false}
$probe="const net=require('node:net');const s=net.connect({host:'1.1.1.1',port:443});s.setTimeout(5000);s.once('connect',()=>{s.destroy();process.exit(0)});s.once('timeout',()=>{s.destroy();process.exit(2)});s.once('error',e=>{s.destroy();console.log(e.code);process.exit(['EPERM','EACCES'].includes(e.code)?3:4)});"
try {
 if(Test-Path -LiteralPath $proofPath){throw 'Network proof already exists'}
 if((Get-FileHash -LiteralPath $AdmissionPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $AdmissionSha256){throw 'Admission digest mismatch'}
 $admission=Get-Content -LiteralPath $AdmissionPath -Raw | ConvertFrom-Json
 if($admission.selected -ne $true -or $admission.target -cne 'windows-x64' -or $Stage -notin $admission.stages){throw 'Stage not admitted'}
 if(-not [String]::Equals([IO.Path]::GetFullPath($NodePath),[IO.Path]::GetFullPath($admission.tools.node.path),[StringComparison]::OrdinalIgnoreCase)){throw 'Node path differs from admission'}
 if((Get-FileHash -LiteralPath $NodePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $admission.tools.node.sha256){throw 'Node identity mismatch'}
 & $NodePath (Join-Path $KitPath 'selection-preflight.mjs') --admission $AdmissionPath --sha256 $AdmissionSha256 --target windows-x64 --stage $Stage
 if($LASTEXITCODE -ne 0){throw 'Exact independent preparation selection preflight failed'}
 if((Get-Service -Name mpssvc).Status.ToString() -cne 'Running'){throw 'Firewall service must already run; wrapper never changes service state'}
 foreach($store in @('PersistentStore','ActiveStore')) {
  $profiles=@(Get-NetFirewallProfile -PolicyStore $store)
  if($profiles.Count -ne 3 -or @($profiles | Where-Object {$_.Enabled.ToString() -cne 'True'}).Count -ne 0){throw 'All firewall profiles must already be enabled; wrapper never changes profiles'}
 }
 $programs=@($admission.network.programs)
 if($programs.Count -lt 5){throw 'Explicit Node, Python, browser, CLI and GUI application rule paths are required'}
 $seen=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
 foreach($program in $programs) {
  $path=[IO.Path]::GetFullPath($program.path)
  if(-not $seen.Add($path) -or $program.sha256 -notmatch '^[a-f0-9]{64}$'){throw 'Duplicate program or missing digest'}
  if(Test-Path -LiteralPath $path){
   $item=Get-Item -LiteralPath $path -Force
   if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'Executable path is not regular'}
   if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $program.sha256){throw 'Executable identity mismatch'}
  } elseif(-not $path.StartsWith([IO.Path]::GetFullPath($Workspace)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Only exact future extracted runtime paths may initially be absent'}
 }
 foreach($required in @($NodePath,$admission.tools.python.path,$admission.tools.browser.path)){if(-not $seen.Contains([IO.Path]::GetFullPath($required))){throw 'A launcher/browser/Python executable is not covered'}}
 $runtimeRoot=Join-Path $Workspace "qualification/$Stage/runtime with space Ω 日本語/gridcraft-current-windows-x64"
 $runtimeManifest=if($Stage -ceq 'public'){$admission.publicRuntime.runtimeFiles}else{(Get-Content -LiteralPath (Join-Path $Workspace 'gridcraft-current-windows-x64/MANIFEST.json') -Raw | ConvertFrom-Json).files}
 foreach($name in @('gridcraft-cli.exe','gridcraft.exe')) {
  $expectedPath=Join-Path $runtimeRoot "bin/$name"
  if(-not $seen.Contains([IO.Path]::GetFullPath($expectedPath))){throw 'A current extracted native executable is not covered'}
  $pinned=@($runtimeManifest | Where-Object {$_.path -ceq "bin/$name"})
  $mapped=@($programs | Where-Object {[String]::Equals([IO.Path]::GetFullPath($_.path),[IO.Path]::GetFullPath($expectedPath),[StringComparison]::OrdinalIgnoreCase)})
  if($pinned.Count -ne 1 -or $mapped.Count -ne 1 -or $mapped[0].sha256 -cne $pinned[0].sha256){throw 'Runtime firewall identity differs from runtime manifest'}
 }
 & $NodePath -e $probe
 if($LASTEXITCODE -ne 0){throw 'Outbound positive control failed; no denial evidence can be inferred'}
 $proof.positiveControlConnected=$true
 foreach($program in $programs) {
  $name=$prefix+'-'+$ownedRules.Count
  $ownedRules += $name
  New-NetFirewallRule -Name $name -DisplayName $name -PolicyStore PersistentStore -Direction Outbound -Action Block -Enabled True -Profile Any -Program ([IO.Path]::GetFullPath($program.path)) | Out-Null
  $rules=@(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore)
  if($rules.Count -ne 1 -or $rules[0].Action.ToString() -cne 'Block' -or $rules[0].Direction.ToString() -cne 'Outbound' -or $rules[0].Enabled.ToString() -cne 'True'){throw 'Firewall rule not effective'}
  $filters=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rules[0] -PolicyStore ActiveStore)
  if($filters.Count -ne 1 -or -not [String]::Equals($filters[0].Program,[IO.Path]::GetFullPath($program.path),[StringComparison]::OrdinalIgnoreCase)){throw 'Firewall program differs'}
 }
 $denial=@(& $NodePath -e $probe)
 if($LASTEXITCODE -ne 3 -or ($denial -join '').Trim() -notin @('EPERM','EACCES')){throw 'External permission denial was not established'}
 $proof.nodeDirectIpDenied=$true
 & $NodePath (Join-Path $KitPath 'pipeline.mjs') --stage $Stage --target windows-x64 --workspace $Workspace --admission $AdmissionPath --admission-sha256 $AdmissionSha256
 if($LASTEXITCODE -ne 0){throw 'Restricted runtime stage failed'}
 foreach($program in $programs){if(Test-Path -LiteralPath $program.path){if((Get-FileHash -LiteralPath $program.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $program.sha256){throw 'Program changed during qualification'}}}
 $proof.programs=$programs
}catch {$primaryError=$_.Exception.Message}finally {
 foreach($name in $ownedRules) {
  try{Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore}catch{$cleanupErrors.Add("Remove rule $name : $($_.Exception.Message)")}
  $absent=$true
  foreach($store in @('PersistentStore','ActiveStore')){try{if(@(Get-NetFirewallRule -PolicyStore $store | Where-Object {$_.Name -ceq $name}).Count -ne 0){$absent=$false;$cleanupErrors.Add("Rule remains in $store : $name")}}catch{$absent=$false;$cleanupErrors.Add($_.Exception.Message)}}
  $removed += [pscustomobject]@{name=$name;absentFromBothStores=$absent}
 }
}
$proof.rulesRemoved=$removed
$proof.cleanupVerified=($cleanupErrors.Count -eq 0)
$proof.error=$primaryError
$proof.cleanupErrors=@($cleanupErrors)
$proof.passed=($null -eq $primaryError -and $cleanupErrors.Count -eq 0)
$directory=Split-Path -Parent $proofPath
[IO.Directory]::CreateDirectory($directory) | Out-Null
$stream=[IO.File]::Open($proofPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($false));try{$writer.Write(($proof | ConvertTo-Json -Depth 20)+"`n")}finally{$writer.Dispose()}}finally{$stream.Dispose()}
if(-not $proof.passed){throw 'Windows qualification or rule cleanup failed; inspect WINDOWS-NETWORK.json'}
