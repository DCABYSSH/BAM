cls

Write-Host ""
Write-Host @"
▄████▄   ██▓    ▓█████ ▄▄▄       ██▀███       ██████   ██████ 
▒██▀ ▀█  ▓██▒    ▓█   ▀▒████▄    ▓██ ▒ ██▒   ▒██    ▒ ▒██    ▒ 
▒▓█    ▄ ▒██░    ▒███  ▒██  ▀█▄  ▓██ ░▄█ ▒   ░ ▓██▄   ░ ▓██▄   
▒▓▓▄ ▄██▒▒██░    ▒▓█  ▄░██▄▄▄▄██ ▒██▀▀█▄       ▒   ██▒  ▒   ██▒
▒ ▓███▀ ░░██████▒░▒████▒▓█   ▓██▒░██▓ ▒██▒   ▒██████▒▒▒██████▒▒
░ ░▒ ▒  ░░ ▒░▓  ░░░ ▒░ ░▒▒   ▓▒█░░ ▒▓ ░▒▓░   ▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░
░  ▒   ░ ░ ▒  ░ ░ ░  ░ ▒   ▒▒ ░  ░▒ ░ ▒░   ░ ░▒  ░ ░░ ░▒  ░ ░
░          ░ ░      ░    ░   ▒     ░░   ░    ░  ░  ░  ░  ░  
░ ░          ░  ░   ░  ░     ░  ░   ░              ░        ░   
"@ -ForegroundColor Magenta
Write-Host ""
Write-Host "                                                                                           made by DCABYSSH"
Write-Host ""

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  Write-Warning "This script requires Administrator privileges. Please run as Administrator."
  exit
}

function Get-OldestConnectTime {
    $oldestLogon = Get-CimInstance -ClassName Win32_LogonSession | 
        Where-Object {$_.LogonType -eq 2 -or $_.LogonType -eq 10} | 
        Sort-Object -Property StartTime | 
        Select-Object -First 1
    if ($oldestLogon) {
        return $oldestLogon.StartTime
    } else {
        return $null
    }
}

function Get-DeviceMappings {
    $DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)
    $TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    $Kernel32 = $TypeBuilder.CreateType()
    $Max = 65536
    $StringBuilder = New-Object System.Text.StringBuilder($Max)
    $driveMappings = Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
        $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)
        if ($ReturnLength) {
            @{
                DriveLetter = $_.DriveLetter
                DevicePath = $StringBuilder.ToString().ToLower()
            }
        }
    }
    return $driveMappings
}

function Convert-DevicePathToDriveLetter {
    param (
        [string]$DevicePath,
        $DeviceMappings
    )
    foreach ($mapping in $DeviceMappings) {
        if ($DevicePath -like ($mapping.DevicePath + "*")) {
            return $DevicePath -replace [regex]::Escape($mapping.DevicePath), $mapping.DriveLetter
        }
    }
    return $DevicePath
}

function Get-FileSignature {
    param ([string]$FilePath)
    if (Test-Path $FilePath) {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath
        if ($signature.Status -eq 'Valid') {
            if ($signature.SignerCertificate.Subject -like "*Manthe Industries, LLC*") {
                return "Not signed (vapeclient)"
            }
            if ($signature.SignerCertificate.Subject -like "*Slinkware*") {
                return "Not signed (slinky)"
            } else {
                return "Signed"
            }
        } else {
            return "Not signed"
        }
    } else {
        return "Deleted"
    }
}

$oldestConnectTime = Get-OldestConnectTime
$deviceMappings = Get-DeviceMappings
$ErrorActionPreference = 'SilentlyContinue'

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
    Try { New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE }
    Catch {}
}

$bv = @("bam", "bam\State")
$Users = @()
foreach ($ii in $bv){
    $Users += Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
}

if ($Users.Count -eq 0) {
    Write-Host "No BAM entries found. This system may not be compatible."
    exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -ErrorAction SilentlyContinue).DaylightBias

$Bam = @()
foreach ($Sid in $Users) {
    foreach ($rp in $rpath){
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        Try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        } Catch { $User = "" }
        
        foreach ($Item in $BamItems){
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
            if ($Key.Length -eq 24){
                $Hex = [System.BitConverter]::ToString($Key[7..0]) -replace "-",""
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex,16))).AddMinutes($Bias) -Format "yyyy-MM-dd HH:mm:ss") 
                if ([DateTime]::ParseExact($TimeUser, "yyyy-MM-dd HH:mm:ss", $null) -ge $oldestConnectTime) {
                    $f = if (((Split-Path -Path $Item) | ConvertFrom-String -Delimiter "\\").P3 -match '\d{1}') { Split-Path -Leaf ($Item).TrimStart() } else { $Item }
                    $path = Convert-DevicePathToDriveLetter -DevicePath $Item -DeviceMappings $deviceMappings
                    $signature = Get-FileSignature -FilePath $path
                    $Bam += [PSCustomObject]@{
                        'Last Execution User Time' = $TimeUser
                        Path = $path
                        'Digital Signature' = $signature
                        'File Name' = $f
                    }
                }
            }
        }
    }
}

$ErrorActionPreference = 'Continue'

$ContenidoHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BAM Signature</title>
...
</head>
<body>
<main>
<table id="entriesTable">
<thead>
<tr>
<th data-sort="time">Last Execution</th>
<th data-sort="path">Path</th>
<th data-sort="signature">Digital Signature</th>
<th data-sort="fileName">File Name</th>
</tr>
</thead>
<tbody></tbody>
</table>
</main>
<footer>
Made by DCABYSSH
</footer>
<script>
const entries = [
'@

foreach ($entry in $Bam) {
    $escapedTime = $entry.'Last Execution User Time'.Replace('\','\\')
    $escapedPath = $entry.Path.Replace('\','\\')
    $escapedSignature = $entry.'Digital Signature'.Replace('\','\\')
    $escapedFileName = $entry.'File Name'.Replace('\','\\')
    $ContenidoHtml += @"
        {
          time: '$escapedTime',
          path: '$escapedPath',
          signature: '$escapedSignature',
          fileName: '$escapedFileName'
        },
"@
}

$ContenidoHtml += @'
];
</script>
</body>
</html>
'@

$htmlFilePath = Join-Path $env:TEMP "BAMKeyEntries.html"
$ContenidoHtml | Out-File -FilePath $htmlFilePath -Encoding UTF8
Start-Process $htmlFilePath
