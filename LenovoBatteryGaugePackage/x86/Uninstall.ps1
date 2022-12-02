trap {"An error trapped..."}


$PackageName = "LenovoBatteryGaugePackage"
$PathToPluginDir = "$env:ProgramData\Lenovo\ImController\Plugins"
$PathToPackageDir = "$PathToPluginDir\$PackageName"
$LogFileName = ("$PackageName" + ".Uninstall." + (Get-Date -Format "-yyyy_MM_dd-HH-mm-ss") + ".txt")
$PathToLogsDir = "$env:ProgramData\Lenovo\Modern\Logs"
$PathToLogFile = "$PathToLogsDir\$LogFileName"
$UninstallFileName = $MyInvocation.MyCommand.Name
$InstallFileName = "Install.ps1"
[bool]$EnableLogging = $false
try { $EnableLogging = ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Lenovo\Modern\Logs" -Name "ImController.Service") -eq 0 ) } catch{}

$PSDefaultParameterValues["Write-Log:pathToLogFile"]=$PathToLogFile
$PSDefaultParameterValues["Write-Log:enableLogging"]=$EnableLogging

Function Check-Is64BitProcess()
{
	return [Environment]::Is64BitProcess
}

Function Check-Is64BitOS()
{
	return [Environment]::Is64BitOperatingSystem
}

Function Check-IsWow64()
{
	return !(Check-Is64BitProcess) -and (Check-Is64BitOS)
}

Function Check-Is64BitPackage()
{
	return $PSScriptRoot.ToLower().Contains("x64".ToLower())
}

function Write-Log
{
    [CmdletBinding()]
    param(
		[Parameter(
			Mandatory=$false,
			Position=1,
			ValueFromPipeline=$true
		)]
		[PSObject[]]$inputObject,
        [string]$pathToLogFile=".\" + [System.IO.Path]::GetFileName($MyInvocation.ScriptName) + ".log",
		[bool]$enableLogging=$true
    )

    $obj=$null
    if($input -ne $null)
    {
        $obj=$input
    }
    else
    {
        $obj=$inputObject
    }

    Out-Host -InputObject $obj
    if($enableLogging)
    {
		$timeStamp = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss  ')
		$objTS = $timeStamp + $obj

		if( -not(Test-Path $pathToLogFile)) { New-Item -Path (Split-Path $pathToLogFile) -Name (Split-Path $pathToLogFile -leaf) -ItemType File -force | Out-Null }
	  	Out-File -InputObject $objTS -FilePath $pathToLogFile -Encoding unicode -Append -Width 200
    }
}

function Get-CurrentActiveUser
{
	$activeUser = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername -EA stop | Select UserName -Unique|%{"{0}" -f $_.UserName.ToString().Split('\')[1]}
	$objUser = New-Object System.Security.Principal.NTAccount("$activeUser")
	$objUser.Value
}

Function CheckCVLibrarySignature($moduleFullPathName)
{
	$ASValid = $False
	$ASCheck  =Get-AuthenticodeSignature $moduleFullPathName
	if($ASCheck -ne $null)
	{
		if ( ($ASCheck.Status.ToString()).ToLower() -eq "valid" )
		{
			$ASValid = $True
		}
	}

	if($ASValid -eq $False)
	{
		Exit
	}
}


if(Check-Is64BitOS)
{
	$OS_BITNESS=64
}
else
{
	$OS_BITNESS=32
}
	
if(Check-Is64BitProcess)
{
	$PS_BITNESS=64
}
else
{
	$PS_BITNESS=32
}

if(Check-Is64BitPackage)
{
	$PK_BITNESS=64
}
else
{
	$PK_BITNESS=32
}

if ($OS_BITNESS -eq 64)
{
	$arch="x64"
}
else
{
	$arch="x86"
}

# ::***********************************************************************************************
# :: Definition: BatteryGaugeIconControl
$applicationName = "$env:SystemRoot\system32\rundll32.exe"
$PathPackageDirDest = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage"
$commandline = " $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll, "
$cmdLineDll = "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
$HideBg="HideBatteryGauge"
$UnloadBg="UnloadBatteryGaugeFromExplorer"

# Check file signature validation
CheckCVLibrarySignature("$PSScriptRoot\Lenovo.CertificateValidation.dll")

Import-Module "$PSScriptRoot\Lenovo.CertificateValidation.dll"

Function IsTrustedAssemblyFile($fullFileName)
{
	 $validRet = [Lenovo.CertificateValidation.FileValidator]::GetTrustStatus($fullFileName)
	 if( ($validRet -eq 0) -or ($validRet -eq "FileTrusted") -or ($validRet -eq [Lenovo.CertificateValidation.TrustStatus]::FileTrusted))
	 {
	 	 return 1
	 }
	 return 0
}


# Notice: ImpersonnateLoggedOnUser in exe
Function BatteryGaugeCtrlByApp($commandName)
{
	# Execute from dest dir
	$pathAppFile = "$PathPackageDirDest\$arch\BGHelper.exe"
	$pathDllFile = "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if((-not(Test-Path -Path "$pathDllFile" -PathType Leaf)) -or (-not(Test-Path -Path "$pathAppFile" -PathType Leaf)))
	{
		# Execute from source dir
		$pathAppFile = "$PathPackageDirSource\$arch\BGHelper.exe"
		$pathDllFile = "$PathPackageDirSource\$arch\LenovoBatteryGaugePackage.dll"
	}

	if((Test-Path -Path "$pathDllFile" -PathType Leaf) -and (Test-Path -Path "$pathAppFile" -PathType Leaf))
	{
		if(IsTrustedAssemblyFile($pathAppFile) -eq 1)
		{
			powershell $pathAppFile $commandName
			if ($? -eq $true)
			{
				Write-Log "BatteryGaugeCtrlByApp OK: ReturnCode=$LastExitCode, CmdName=$commandName"
				return 1
			}
		}
	}

	Write-Log "BatteryGaugeCtrlByApp($commandName) failed! ReturnCode=$LastExitCode"
	return 0
}

# Notice: ImpersonnateLoggedOnUser in dll
Function BatteryGaugeCtrlByRundll32($commandName)
{
	#Param(
	#	[string]$commandName,
	#	[bool]$impersonnateLoggedOnUser = $True
	#)

	# Execute from dest dir
	$pathCmdFile = "$PathPackageDirDest\$arch\$commandName.lnk"
	$pathDllFile = "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if((-not(Test-Path -Path "$pathDllFile" -PathType Leaf)) -or (-not(Test-Path -Path "$pathCmdFile" -PathType Leaf)))
	{
		# Execute from source dir
		$pathCmdFile = "$PathPackageDirSource\$arch\$commandName.lnk"
		$pathDllFile = "$PathPackageDirSource\$arch\LenovoBatteryGaugePackage.dll"
	}

	if((Test-Path -Path "$pathDllFile" -PathType Leaf) -and (Test-Path -Path "$pathCmdFile" -PathType Leaf))
	{
		if(IsTrustedAssemblyFile($pathDllFile) -eq 1)
		{
			# IMPORT: the 'blank space' MUST reserve!!!
			$commandParam = " $pathDllFile, " + $commandName
			powershell $applicationName $commandParam
			if ($? -eq $true)
			{
				Write-Log "BatteryGaugeIconControlEx OK: ReturnCode=$LastExitCode, CmdName=$commandName"
				return 1
			}
		}
	}

	Write-Log "BatteryGaugeIconControlEx($commandName) failed! ReturnCode=$LastExitCode"
	return 0
}

Function BatteryGaugeIconControlEx($commandName)
{
	$BGCtrlRet = BatteryGaugeCtrlByRundll32($commandName)
	if ($BGCtrlRet -eq 0)
	{
		$BGCtrlRet = BatteryGaugeCtrlByApp($commandName)	
	}

	return $BGCtrlRet
}


# Kill BG processes directly. Only call when necessary.
Function StopBGProcessDirectly
{
	Write-Log "Kill BG related processes, which run from: `"$PathPackageDirDest`" "
	
	(Get-Process | Select-Object Path,Id,Name | Where-Object {$_.Path -Ilike "$PathPackageDirDest*"}) | Stop-Process -Force
}

Function StopProcessByTaskkill
{
	Write-Log "Kill BG special processes if running"
	$TaskkillPath = "$env:SystemRoot\System32\taskkill.exe"

	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM HeartbeatMetrics.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM IdeaIntelligentCoolingMetrics.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM QuickSetting.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM QuickSettingEx.exe"
	Start-Process -NoNewWindow -Wait -FilePath $TaskkillPath -ArgumentList "/F /T /IM QSHelper.exe"
}

# Check if dll file is still used by explorer
Function IsFileUsedByExplorer
{
	param([string]$dllFileName)

	$IsInUsed = $false
	$TaskListRet = tasklist /M "$dllFileName"
	$IsExplorerLike = $TaskListRet -like "explorer*"
	if($IsExplorerLike -ne $false)
	{  
		$IsInUsed = (($IsExplorerLike).ToLower()).Contains("explorer")
	}

	return $IsInUsed
}


trap 
{
	"An error trapped"
	$TrapError = $_.Exception
	$TrapErrorMsg = $TrapError.Message 
	$TrapLine = $_.InvocationInfo.ScriptLineNumber	
	Write-Log "Caught exception( trapped error ) at line[$TrapLine]: Msg= $TrapErrorMsg"
}

Write-Log "Below logs come from $PSCommandPath"
Write-Log "OperatingSystem=[$OS_BITNESS bit], Process=[$PS_BITNESS bit], Package=[$PK_BITNESS bit]"

if ($PS_BITNESS -eq 32)
{
	if ($PK_BITNESS -eq 64)
	{
		if ($OS_BITNESS -eq 32)
		{
			Write-Log "cannot install a 64 bit package in an 32 bit os."
		}
		else
		{
			Write-Log "Package bitness is 64 but process is 32.  Relaunching as 64"
			$PS64BITPATH="$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\PowerShell.exe"
			Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PS64BITPATH -ArgumentList `"$PSCommandPath`""
			Start-Process -NoNewWindow -Wait -FilePath $PS64BITPATH -ArgumentList "$PSCommandPath" *>&1 | Write-Log
			Write-Log "Completed re-running as 64 bit"
			Exit
		}
	}
}
elseif ($PS_BITNESS -eq 64)
{
	if ($PK_BITNESS -eq 32)
	{
		Write-Log "Package bitness is 32 but process is 64.  Relaunching as 32"
		$PS32BITPATH="$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\PowerShell.exe"
		Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PS32BITPATH -ArgumentList `"$PSCommandPath`""
		Start-Process -NoNewWindow -Wait -FilePath $PS32BITPATH -ArgumentList "$PSCommandPath" *>&1 | Write-Log
		Write-Log "Completed re-running as 32 bit"
		Exit
	}
}
else
{
	Write-Log "Package bitness unknown, will exit."
}



# ::***********************************************************************************************
# :: [Remove LenovoBatteryGaugePackage.dll from taskbar]
# ::***********************************************************************************************
Write-Log "Remove LenovoBatteryGaugePackage.dll from taskbar"

$RetryCount = 0
$completed = $false
while(($completed -eq $false) -and ($RetryCount -le 2))
{
	if(BatteryGaugeIconControlEx($UnloadBg) -ne 0 )
	{
		# Wait BGdll to unload from explorer. 1.2 seconds might be enough
		Start-Sleep -Milliseconds 1200
		$completed = $true
		Write-Log "Unload battery gauge from explorer tray sucessful"
	}
	else
	{
		Start-Sleep -Milliseconds 400
		Write-Log "Unload battery gauge from explorer tray failure"
	}
		
	if ($RetryCount -ge 2)
    {
		Write-Log "Error : failed to unload BatteryGauge icon from explorer.."
		#Exit
	}
	$RetryCount++
}


# ::***********************************************************************************************
# :: [Kill active BG processes]:
# ::  QuickSetting.exe,QuickSettingEx.exe,HeartbeatMetrics.exe,SetThinkTouchPad.exe....]
# ::***********************************************************************************************
StopBGProcessDirectly
StopProcessByTaskkill

# ::***********************************************************************************************
# :: [Unregister LenovoBatteryGaugePackage.dll ]
# ::***********************************************************************************************
$RegSvr32Path = "$env:SystemRoot\System32\regsvr32.exe"
Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList `"/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll`""
Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList "/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll" *>&1 | Write-Log
if($? -ne $true)
{
	Write-Log "Unregistry battery gauge from system return code $LastExitCode"
}

# ::***********************************************************************************************
# :: [Unregister PluginsContract.dll ]
# ::***********************************************************************************************
Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PathPackageDirDest\$arch\RegAsm.exe -ArgumentList `"/silent /u $PathPackageDirDest\$arch\PluginsContract.dll`""
Start-Process -NoNewWindow -Wait -FilePath $PathPackageDirDest\$arch\RegAsm.exe -ArgumentList "/silent /u $PathPackageDirDest\$arch\PluginsContract.dll" *>&1 | Write-Log
if($? -ne $true)
{
	Write-Log "Unregistry PluginsContract.dll from system return code $LastExitCode"
}

# ::***********************************************************************************************
# :: [Check if LenovoBatteryGaugePackage.dll still running. If running, force to restart explorer]
# ::***********************************************************************************************
Write-Log "Check if BG has been removed from taskbar"

$RetryCount = 0
$completed = $false
while(($completed -eq $false) -and ($RetryCount -le 1))
{
	$BGInUse = IsFileUsedByExplorer "LenovoBatteryGaugePackage.dll"
	$AVInUse = IsFileUsedByExplorer "Lenovo.AssemblyValidation.Native.dll"
	$CVInUse = IsFileUsedByExplorer "Lenovo.CertificateValidation.dll"

	if( ($BGInUse -eq $true) -or ($AVInUse -eq $true) -or ($CVInUse -eq $true) )
	{
		# Force to unload: rename dll, then restart explorer
		Remove-Item -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll" -NewName "LenovoBatteryGaugePackage_bk.dll"  *>&1 | Write-Log

		Remove-Item -Path "$PathPackageDirDest\$arch\Lenovo.AssemblyValidation.Native_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.AssemblyValidation.Native.dll" -NewName "Lenovo.AssemblyValidation.Native_bk.dll"  *>&1 | Write-Log

		Remove-Item -Path "$PathPackageDirDest\$arch\Lenovo.CertificateValidation_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.CertificateValidation.dll" -NewName "Lenovo.CertificateValidation_bk.dll"  *>&1 | Write-Log

		Remove-Item -Path "$PathPackageDirDest\$arch\Newtonsoft.Json_bk.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Newtonsoft.Json.dll" -NewName "Newtonsoft.Json_bk.dll"  *>&1 | Write-Log

		# BG can't load anymore after restart explorer, because file can't be found.
		Stop-Process -ProcessName "explorer"
		Start-Sleep -Milliseconds 400		

		# Rename dll back
		Rename-Item -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage_bk.dll" -NewName "LenovoBatteryGaugePackage.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.AssemblyValidation.Native_bk.dll" -NewName "Lenovo.AssemblyValidation.Native.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Lenovo.CertificateValidation_bk.dll" -NewName "Lenovo.CertificateValidation.dll"  *>&1 | Write-Log
		Rename-Item -Path "$PathPackageDirDest\$arch\Newtonsoft.Json_bk.dll" -NewName "Newtonsoft.Json.dll"  *>&1 | Write-Log
	}
    else
    {
		$completed = $true
    }
		
	if ($RetryCount -ge 1)
    {
		Write-Log "Error : LenovoBatteryGaugePackage.dll is still in use but failed to restart explorer....."
		#Exit
	}
	$RetryCount++
}

Function GetCurrentActiveUserSID
{
	$activeUser = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername -EA stop | Select UserName -Unique|%{"{0}" -f $_.UserName.ToString().Split('\')[1]}
	$objUser = New-Object System.Security.Principal.NTAccount("$activeUser")
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	$strSID.Value
}

# try to remove temporary files, folders?
if($($args[0]) -eq "ForUpdate")
{
	Write-Log "No need to removing Lenovo Battery Gauge temporary folders and user data for upgradation"
}
else
{
	# ::***********************************************************************************************
	# :: Delete BG MaintenanceTask
	# ::***********************************************************************************************
	$SchTasksPath = "$env:SystemRoot\System32\schtasks.exe"
	Write-Log "$SchTasksPath /Delete /TN `"\Lenovo\BatteryGauge\BatteryGaugeMaintenance`" /F"
	powershell $SchTasksPath /Delete /TN "\Lenovo\BatteryGauge\BatteryGaugeMaintenance" /F  *>&1 | Write-Log

	# Rename QSHelper
	Rename-Item -Path "$PathPackageDirDest\$arch\QSHelper.exe" -NewName "QSHelper_bk.exe"  *>&1 | Write-Log

	# ::***********************************************************************************************
	# :: [Remove Lenovo Battery Gauge Registry Entries ]
	# ::***********************************************************************************************
	$RegPath = "$env:SystemRoot\System32\reg.exe"
	Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList `"delete HKLM\Software\Lenovo\QuickSetting /v Location /f`""
	Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList "delete HKLM\Software\Lenovo\QuickSetting /v Location /f" *>&1 | Write-Log
	if($? -ne $true)
	{
		Write-Log "Unregistry battery gauge from system return code $LastExitCode"
	}

	Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList `"delete HKLM\Software\Lenovo\QuickSetting /v Path /f`""
	Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList "delete HKLM\Software\Lenovo\QuickSetting /v Path /f" *>&1 | Write-Log
	if($? -ne $true)
	{
		Write-Log "Delete registry value `"Path`" from `"HKLM\Software\Lenovo\QuickSetting`" return code $LastExitCode"
	}

	Write-Log "Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList `"delete HKLM\Software\Lenovo\QuickSetting /f`""
	Start-Process -NoNewWindow -Wait -FilePath $RegPath -ArgumentList "delete HKLM\Software\Lenovo\QuickSetting /f" *>&1 | Write-Log
	if($? -ne $true)
	{
		Write-Log "Delete registry key `"HKLM\Software\Lenovo\QuickSetting`" return code $LastExitCode"
	}


	# ::***********************************************************************************************
	# :: [Remove Lenovo Battery Gauge temporary folders ]
	# ::***********************************************************************************************
    $pathReg = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
    Get-ItemProperty -Path $pathReg | ForEach-Object { $SidStr = $_ | Select-Object -Property PSChildName -Unique|%{"{0}" -f $_.PSChildName.ToString()} 
    REG DELETE HKU\$SidStr\Software\Lenovo\BatteryGauge  /f}

	Write-Log "Remove Lenovo Battery Gauge temporary folders"
	$ACTIVEUSER=Get-CurrentActiveUser
	Write-Log "Remove-Item -Recurse -Force `"$env:ProgramData\Lenovo\BatteryGauge`""
	Remove-Item -Recurse -Force "$env:ProgramData\Lenovo\BatteryGauge" *>&1 | Write-Log

	Write-Log "Remove-Item -Recurse -Force `"$env:HomeDrive\Users\$ACTIVEUSER\AppData\Local\Lenovo\BatteryGauge`""
	Remove-Item -Recurse -Force "$env:HomeDrive\Users\$ACTIVEUSER\AppData\Local\Lenovo\BatteryGauge" *>&1 | Write-Log

	Write-Log "Remove-Item -Recurse -Force `"$env:HomeDrive\Users\$ACTIVEUSER\AppData\LocalLow\Lenovo\batterygauge`""
	Remove-Item -Recurse -Force "$env:HomeDrive\Users\$ACTIVEUSER\AppData\LocalLow\Lenovo\batterygauge" *>&1 | Write-Log

    Write-Log "Remove-Item -Recurse -Force `"$env:ProgramData\Lenovo\settings_batterygaugeplugin`""
	Remove-Item -Recurse -Force "$env:ProgramData\Lenovo\settings_batterygaugeplugin" *>&1 | Write-Log
	
	$au = GetCurrentActiveUserSID
	Write-Log "Remove-ItemProperty -Path HKCU:\SOFTWARE\Lenovo\BatteryGaugeToast\ResetEyeCareMode"
	Write-Log "user = $au"
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS *>&1 | Write-Log
	Remove-ItemProperty -Path "HKU:$au\SOFTWARE\Lenovo\BatteryGaugeToast" -Name "ResetEyeCareMode" -ErrorAction SilentlyContinue *>&1 | Write-Log
	Remove-ItemProperty -Path "HKU:$au\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LenovoVantageToolbar" -ErrorAction SilentlyContinue *>&1 | Write-Log
	Remove-PSDrive -Name HKU *>&1 | Write-Log
}

Write-Log "Uninstall success"
Exit
# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDKkVptQ/kxNPq8
# HsZScRy4y1ITbFRCmwgxu/Fk58mo7qCCIS8wggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0G
# CSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTla
# MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UE
# AxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBp
# bmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJ
# UVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+e
# DzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47q
# UT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL
# 6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c
# 1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052
# FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+
# onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/w
# ojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1
# eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uK
# IqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7p
# XcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgw
# BgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgw
# FoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQM
# MAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6
# MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# Um9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJ
# KoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7
# x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGId
# DAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7g
# iqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6
# wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx
# 2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5kn
# LD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3it
# TK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7
# HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUV
# mDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKm
# KYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8
# MIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
# RzQwHhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1
# M4zrPYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZ
# wZHMgQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI
# 8IrgnQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGi
# TUyCEUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLm
# ysL0p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3S
# vUQakhCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tv
# k2E0XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+
# 960IHnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3s
# MJN2FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FK
# PkBHX8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1H
# s/q27IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDAzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwHAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQAD
# ggIBADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L
# /Z6jfCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHV
# UHmImoqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rd
# KOtfJqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK
# 6Wrxoj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43N
# b3Y3LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4Z
# XDlx4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvm
# oLr9Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8
# y4+ICw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMM
# B0ug0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+F
# SCH5Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGxjCCBK6gAwIB
# AgIQCnpKiJ7JmUKQBmM4TYaXnTANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIyMDMy
# OTAwMDAwMFoXDTMzMDMxNDIzNTk1OVowTDELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMSQwIgYDVQQDExtEaWdpQ2VydCBUaW1lc3RhbXAgMjAy
# MiAtIDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC5KpYjply8X9ZJ
# 8BWCGPQz7sxcbOPgJS7SMeQ8QK77q8TjeF1+XDbq9SWNQ6OB6zhj+TyIad480jBR
# DTEHukZu6aNLSOiJQX8Nstb5hPGYPgu/CoQScWyhYiYB087DbP2sO37cKhypvTDG
# FtjavOuy8YPRn80JxblBakVCI0Fa+GDTZSw+fl69lqfw/LH09CjPQnkfO8eTB2ho
# 5UQ0Ul8PUN7UWSxEdMAyRxlb4pguj9DKP//GZ888k5VOhOl2GJiZERTFKwygM9tN
# JIXogpThLwPuf4UCyYbh1RgUtwRF8+A4vaK9enGY7BXn/S7s0psAiqwdjTuAaP7Q
# WZgmzuDtrn8oLsKe4AtLyAjRMruD+iM82f/SjLv3QyPf58NaBWJ+cCzlK7I9Y+rI
# roEga0OJyH5fsBrdGb2fdEEKr7mOCdN0oS+wVHbBkE+U7IZh/9sRL5IDMM4wt4sP
# XUSzQx0jUM2R1y+d+/zNscGnxA7E70A+GToC1DGpaaBJ+XXhm+ho5GoMj+vksSF7
# hmdYfn8f6CvkFLIW1oGhytowkGvub3XAsDYmsgg7/72+f2wTGN/GbaR5Sa2Lf2GH
# BWj31HDjQpXonrubS7LitkE956+nGijJrWGwoEEYGU7tR5thle0+C2Fa6j56mJJR
# zT/JROeAiylCcvd5st2E6ifu/n16awIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQD
# AgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9z
# KXaaL3WMaiCPnshvMB0GA1UdDgQWBBSNZLeJIf5WWESEYafqbxw2j92vDTBaBgNV
# HR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEF
# BQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQANLSN0ptH1+OpLmT8B5PYM5K8WndmzjJeCKZxDbwEtqzi1
# cBG/hBmLP13lhk++kzreKjlaOU7YhFmlvBuYquhs79FIaRk4W8+JOR1wcNlO3yMi
# bNXf9lnLocLqTHbKodyhK5a4m1WpGmt90fUCCU+C1qVziMSYgN/uSZW3s8zFp+4O
# 4e8eOIqf7xHJMUpYtt84fMv6XPfkU79uCnx+196Y1SlliQ+inMBl9AEiZcfqXnSm
# WzWSUHz0F6aHZE8+RokWYyBry/J70DXjSnBIqbbnHWC9BCIVJXAGcqlEO2lHEdPu
# 6cegPk8QuTA25POqaQmoi35komWUEftuMvH1uzitzcCTEdUyeEpLNypM81zctoXA
# u3AwVXjWmP5UbX9xqUgaeN1Gdy4besAzivhKKIwSqHPPLfnTI/KeGeANlCig69sa
# UaCVgo4oa6TOnXbeqXOqSGpZQ65f6vgPBkKd3wZolv4qoHRbY2beayy4eKpNcG3w
# LPEHFX41tOa1DKKZpdcVazUOhdbgLMzgDCS4fFILHpl878jIxYxYaa+rPeHPzH0V
# rhS/inHfypex2EfqHIXgRU4SHBQpWMxv03/LvsEOSm8gnK7ZczJZCOctkqEaEf4y
# mKZdK5fgi9OczG21Da5HYzhHF1tvE9pqEG4fSbdEW7QICodaWQR2EaGndwITHDCC
# B2cwggVPoAMCAQICEAQeEMwPIHXPhEYRSj3cLPwwDQYJKoZIhvcNAQELBQAwaTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAy
# MDIxIENBMTAeFw0yMTA5MTMwMDAwMDBaFw0yMjA5MTMyMzU5NTlaMGwxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEUMBIGA1UEBxMLTW9ycmlz
# dmlsbGUxDzANBgNVBAoTBkxlbm92bzEMMAoGA1UECxMDRzA4MQ8wDQYDVQQDEwZM
# ZW5vdm8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDqY0eTJU5Yy7d3
# dou+uAaNsyjtaMI6/ww9IiQAduFRoFLT6QRkdYvRhAqiz5m5E2uV0St9mBmAEbR8
# wLFQ9UeJtq9LRuO+R7g/kaHteownfhE52ra4tMu4WCGFVtBSt5ppAemvceJ+detF
# Sff4eORgz9VGHxaZeOQycuUa2r//jhB5rLbORZL5k+YlA/gv2VjVM13yPRjt2pwC
# ozQRjumKnTtxkH1zLWSaLYtKW6+MFPmhT27h8KttCZzb+JlhiLF5Hcxr9iIi+ptD
# L3M2W/v7ZzsXQfAnoTkwPEgFkSYuI+ThfJYR5T4jQqDtcFcNQUTLsLZilHm/GJrS
# vhZFxdIj0vMbZeSaP33Km5bCQwwpmYrPIoGIx4GFXanAp1a3PnfbRY1M/bisV1j5
# eyIuoUIgfbEO8pNEK5Ix3xZG1Tabn8hUBeJ5NXU+8Ps3lxq7smIIV3iytI7YP0u4
# KuVl6RTzpvNOL36YHWl28L9oV5EZQtBGoXRcaToOtAnNBiVRIm5QF6X9suUDFv7S
# 7V81Ds1t2L/ZyfG6xOA4f4E5rmfRkegv9ao+WZRISyc64EcYAqFfXn6OBBY1exob
# uyrFY9lmQGRR4WCn5GBHh4QDEUY4xWxTwrRfglyH2GrCqWh0OryTOzgMXGRm/KV3
# 7TJ5V/3mWvpQ+tAzb35MPlANYHocCQIDAQABo4ICBjCCAgIwHwYDVR0jBBgwFoAU
# aDfg67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYEFCGo3FvTjiZDq+YCPTCWRQrh
# XdBjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwPgYDVR0gBDcwNTAzBgZn
# gQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BT
# MIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIx
# Q0ExLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAVUanR6cth
# RQoUKTg3jMsMflEZQKeHJY9Vw4PugMNXBuHyKkXfzGA+nh4G1kzTopMWW7mjyg9r
# JTmVu9dxDE7H2r0BSovOXO0oWHdWRXhRvee5ZsmlShdofSezg6YXXqq271+oAanl
# 3klpAUI3SfgAlEFBTMT9NVmBzX8JYcje3IMAmq+fi92WKwsli/r4+O4f2/alxRH3
# PJCQbrxCD/RfH9s0mx8BAfuH4d3e9r9s56S/9Pkof3wR7Zxq31jw/2Wko10EsUgS
# guMGOYcNxJnFUfmPiwrcVqVZVlgK+bmgF8T7nWRZmmoaqq72HWGCa9YC0JkCgW/f
# uT3RUr6ugx8BlW6o5tHbDSeOxFR6P2RUV/7x1wB9RQFJgvh1idhdFj+nTqU3eXKE
# 5B9Kt4rI2wV0sJsD4AHTnoWa/vk9u5hNcO2ttyQadg08kmsQ+JxHKHw28GEDSGB5
# C+6G9EwS0CpjEM7eoP07pioa895bnEfV66J4ON4Iquhq3FgDY9orkpNkdZshskeq
# TomT3QSPfVcIqU8+HhRuDY8OdZRGfFNwNdruZsVtOSalNZ2luzIAZKiSoWzsmm3F
# ioIitjUvsAJ9zHqJVIs9MjSO9Z00Rbg4ECHIm+crTfy3rvPeOTncnBvz2N+FJCCu
# pcPnHx2OSFjd8IuDmd9xMZQAHAsysREs/TGCBlMwggZPAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MQIQBB4QzA8gdc+ERhFKPdws/DANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCp6YDsAkI0
# dcM/U/Q4ty2pVSFmRxSKovooYB7QfWqudzANBgkqhkiG9w0BAQEFAASCAgBYIfNS
# HU/hOATvoyRvyV53FMU7/sJ0MRaxKIGDK0+4L/dBvgFFQa/dSeTDpQ4/Rj/kI0Ve
# 0ETfynNliB3UfGrxXj4qdXhVFpp7nxJh+Fu9fi673uWYtHd9+1h98ypnJTbgDMq8
# Ha6g3E4OdsuZTwQflnzVY3GwlPJ2Jioa5C4DXurOQQJeVfJEbzQuDzaVlt8PX3kX
# 2t8fXVlmT9s7l0AWKVq9nllsarOE8qSW4aa2a8lCZNssxxPS7/U/1pfXCYPQAJaG
# 3kmXCUCj9wyuOSu3/5RCOvFOh8ibXRtDQQHxew9o8/gkvxQbExq1CH3sRH0Xtu8D
# GYl+tcW6Yv3wAPTlp+q68PHCtyeuPL5PfNKxWrGGJLTwydREHnTg63oohShn9ojN
# 3Wv0rutLJKN4++6dhf8jIhzxl5KC+eKFGknBMqDm7iaGIlf7QrgMQKsuNxVmlvo+
# Nop2VPOR1K6kU/IU4Ku4U6xzkVoT/FTFvZR+J75EAadBvUZUKhKv14TH322NWY+h
# P6leB+TQpJ2dF3mx/1iC/AjdSUk7dyyfnw0gh3TjkZtsryzpFIyZ3KN0NIQ6KMgf
# ccg73M/MHdjrNTJ3reJNViZoNlL2vb0ahd8fnpx8l4ExEUoRDT9AS2RFqEWeEkyl
# jDjvZjGrsxB0oo57oUcyMy2uSGF3umDKTNEP8KGCAyAwggMcBgkqhkiG9w0BCQYx
# ggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1
# NiBUaW1lU3RhbXBpbmcgQ0ECEAp6SoieyZlCkAZjOE2Gl50wDQYJYIZIAWUDBAIB
# BQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0y
# MjA1MTIwODIwMDRaMC8GCSqGSIb3DQEJBDEiBCAjVx2s7YhnnPMROj3K+MMD/9Mh
# 6byj82QereVHiOplTzANBgkqhkiG9w0BAQEFAASCAgCghwwxsYfdk0kKfUGRG7wG
# YK6bppxmK5TjlUxOMqYbIP4ZQp7z9rGQE3qoi/kM+Q8K6fk0A7J6F1qkxheG/5bk
# bc4N2HjabPBHDvTBU4a67a1qH2URowWuM0GO5IiUrjyyDql5o2let2nep5CVceyn
# Q08JwMjG176izhrA/YVgiJFkVJmBNbszzClN9QpfGfvZ/d/l0CgbQesv1t0HmTdh
# ia0rsu7N4rakuCtK/4lUXhq0LRUWD4pz6n3Ilw2L3sWqH7yd2FbGAbhEWnpm1uKj
# Pr/wi6gqKMsPKdZvedTqHTEeHh/iTH0MiPKxAy04fLWok6Rt0I+TMbNnzoZ4kCd7
# CpYsa/xuXmOPqGYSEUzqvqxJKQIi9859RMKORWvuMa5LFTzFDccE6ddcRKGJTliu
# Jd8qI6d4aQX2m81dRCzHwMHDro2eXvFwrs40/EJsFq7RfZr3QR8Hb+tC0Vvy/FmM
# H7ba+/0clI7xUxdhxdq3TX6P+e4Zzplq/eDdn5oPSOKVFmvAuwb9PbiZeGGx+ZBb
# XtIpAdnBLDEKXrCqK5DDuwSBvZ3nl6xu1kpBfkWIsfuqN/fi2d7mEupcYbGNL7Xe
# lGxmp1xRtyO1h2zQ5UuLHesNBmWEhpY9aIIDf9m7EJbwqTSvenMG52Wh4t6m4jr4
# ahFlgwKBy84rIF0xCqYS3g==
# SIG # End signature block
