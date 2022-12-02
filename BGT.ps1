trap {"An error trapped..."}

# ***********************************************************************************************
# Function for WriteLog
$pathToLogFile = "$PSScriptRoot\BGT\BatteryGaugeLog.txt"
function WriteLog
{
    param([PSObject[]]$inputObject)

    $obj=$null
    if($input -ne $null)
    {
        $obj=$input
    }
    else
    {
        $obj=$inputObject
    }
	
	$objEx = "" + (Get-Date) + "   " + $obj
	
	if( -not(Test-Path $pathToLogFile)) 
	{
		New-Item "$PSScriptRoot\BGT\" -force -type Directory
		New-Item $pathToLogFile -force -type File
	}
	
	Write-Host "$obj"
	
	Out-File -InputObject $objEx -FilePath $pathToLogFile -Encoding unicode -Append -Width 200
}

# ***********************************************************************************************
# Timestamp and path of PS script launching
$CurPSLaunchTime = "-----------> PS LaunchTime is: " + (Get-Date) + ",  LaunchPath = " + $PSScriptRoot
WriteLog $CurPSLaunchTime


# ***********************************************************************************************
# Force to run PS script as Administrator
WriteLog "-----------> Force to run PS script as Administrator"
$CurWinID = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurWinPrcpl = [Security.Principal.WindowsPrincipal]$CurWinID
if( -not $CurWinPrcpl.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	WriteLog "-----------> Please try to run PS script as Administrator....."
	Start-Process "$psHome\powershell.exe"  -ArgumentList "$PSScriptRoot\BGT.ps1"  -verb runas
	Exit
}



# ***********************************************************************************************
# Add Log swith in registry
$PathLenovo = "HKLM:\SOFTWARE\WOW6432Node\Lenovo"
if( -not(Test-Path $PathLenovo)) {New-Item "$PathLenovo"}

$PathModern = "HKLM:\SOFTWARE\WOW6432Node\Lenovo\Modern"
if( -not(Test-Path $PathModern)) {New-Item "$PathModern"}

$PathLogs = "HKLM:\SOFTWARE\WOW6432Node\Lenovo\Modern\Logs"
if( -not(Test-Path $PathLogs)) {New-Item "$PathLogs"}

New-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Lenovo\Modern\Logs" -Name "ImController.Service" -Value "0"                                                                                                                              


# ***********************************************************************************************
# ***********************************************************************************************
# Get plugins related info--before Install BG.
# ***********************************************************************************************
# List all files of ImController-Plugins
WriteLog "-----------> List all files of ImController-Plugins"
powershell tree "$env:ProgramData\Lenovo\ImController\Plugins" /F >"$PSScriptRoot\BGT\Before_Details_ImControllerPlugins.txt"
if (Test-Path "$env:ProgramData\Lenovo\ImController\Plugins\")
{
	powershell ls "$env:ProgramData\Lenovo\ImController\Plugins\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\Before_Details_ImControllerPluginsEx.txt"
	
	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\" -Recurse | 
		Get-Acl | Out-File "$PSScriptRoot\BGT\Before_Details_ImControllerPluginsACL1.txt"

	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\" -Recurse | 
		Get-Acl | Format-List | Out-File "$PSScriptRoot\BGT\Before_Details_ImControllerPluginsACL2.txt"
}

# ***********************************************************************************************
# List all details of BatteryGauge folder, including temperary folder
WriteLog "-----------> List all details of BatteryGauge folder"
if (Test-Path "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\")
{
	powershell ls "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\Before_Details_LenovoBatteryGaugePackage.txt"

	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\" -Recurse | 
		Get-Acl | Out-File "$PSScriptRoot\BGT\Before_Details_LenovoBatteryGaugePackageACL1.txt"

	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\" -Recurse | 
		Get-Acl | Format-List | Out-File "$PSScriptRoot\BGT\Before_Details_LenovoBatteryGaugePackageACL2.txt"
}
else
{WriteLog ("Error -- FileNoFound: " + "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\")}

# PCManager
$PcManagerRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lenovo\PcManager'
$PCManagerInstalled = (Test-Path "Registry::$PcManagerRegPath")
WriteLog "PCManager install status = $PCManagerInstalled"

# Language
$OSLanguageID = (Get-WmiObject -Class Win32_OperatingSystem -Namespace root/cimv2).OSLanguage
WriteLog "Language install ID = $OSLanguageID"
(Get-WmiObject -Class Win32_OperatingSystem -Namespace root/cimv2).MUILanguages | ForEach-Object {
	$MUILan = $_ 
	if ($MUILan -ne $null)
	{
		WriteLog "MUILanguages name = $MUILan"
	}
}


# Copy IMC logs
Copy-Item "$env:SystemRoot\INF\setupapi*.log" "$PSScriptRoot\BGT\" -Force -Recurse
Copy-Item "$env:SystemRoot\INF\setupapi*.txt" "$PSScriptRoot\BGT\" -Force -Recurse

# Set BG ACL 
WriteLog "Begin to set BG ACL"
$PathSetAcl = "$PSScriptRoot\SetAcl.ps1"
if (Test-Path "$PathSetAcl")
{powershell $PathSetAcl}

# IMC
WriteLog "Check IMC status"
$IMCService = Get-Service -Name 'ImControllerService'
if($IMCService -ne $null)
{
	$IMCCanStop = $IMCService.CanStop
	$IMCCanPause = $IMCService.CanPauseAndContinue
	WriteLog "ImControllerStatus status: IMCCanStop=$IMCCanStop, IMCCanPause=$IMCCanPause"
}

if (Test-Path "$env:SystemRoot\Lenovo\ImController\Service\")
{
	powershell ls "$env:SystemRoot\Lenovo\ImController\Service\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\Before_ImController.txt"
}

# VS
WriteLog "Check VantageService status"
$VSService = Get-Service -Name 'LenovoVantageService'
if($VSService -ne $null)
{
	$VSCanStop = $VSService.CanStop
	$VSCanPause = $VSService.CanPauseAndContinue
	WriteLog "LenovoVantageService status: VSCanStop=$VSCanStop, VSCanPause=$VSCanPause"
}

if (Test-Path "C:\Program Files (x86)\Lenovo\VantageService\")
{
	powershell ls "C:\Program Files (x86)\Lenovo\VantageService\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\Before_VantageService.txt"
}

# ITS Service
WriteLog "Check ITSService status"
$ITSService = Get-Service -Name 'LITSSVC'
if($ITSService -ne $null)
{
	$ITSCanStop = $ITSService.CanStop
	$ITSCanPause = $ITSService.CanPauseAndContinue
	WriteLog "ITS Service status: ITSCanStop=$ITSCanStop, ITSCanPause=$ITSCanPause"
}

$ITSSvcExe = "$env:SystemRoot\System32\LNBITSSvc.exe"
if (Test-Path "$ITSSvcExe")
{
	$ITSVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ITSSvcExe").FileVersion
	WriteLog "===> ITS Service version: $ITSVersion."
}

# Retrieve all driver status.
WriteLog "Retrieve all driver status, please wait"
Get-WindowsDriver -Online -All | Out-File "$PSScriptRoot\BGT\Before_WindowsDriverInfo.txt"
#$WinDrvInfoPath = "$PSScriptRoot\BGT\Before_WindowsDriverInfo.txt"
#Get-WmiObject Win32_SystemDriver | Select-Object DisplayName, Name, State, Status, Started, PathName | Out-File $WinDrvInfoPath
#$DriverInfo = Get-WmiObject Win32_SystemDriver
#if($DriverInfo -ne $null)
#{   
#	foreach ($di in $DriverInfo)
#	{
#		$driverPath = $di.PathName
#		$driverVersion = (Get-ChildItem $driverPath).VersionInfo.ProductVersion
#       $driverAccessTime = (Get-ChildItem $driverPath).LastAccessTime
#       $driverWriteTime = (Get-ChildItem $driverPath).LastWriteTime
#
#       $driverInputObject = "Version=$driverVersion, LastAccessTime=$driverAccessTime, LastWriteTime=$driverWriteTime, PathName=$driverPath"
#
#       Out-File -InputObject $driverInputObject -FilePath $WinDrvInfoPath -Encoding unicode -Append -Width 300
#	}
#}


# reg
WriteLog "Export BG registry info"
reg export HKEY_CURRENT_USER\Software\Lenovo "$PSScriptRoot\BGT\Before_HKCULenovo.reg"
reg export HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System "$PSScriptRoot\BGT\Before_HKLMSystem.reg"
reg export HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lenovo\ImController\Packages\LenovoBatteryGaugePackage "$PSScriptRoot\BGT\Before_BGInstallHistory.reg"
reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Lenovo "$PSScriptRoot\BGT\IMCGroupPolicy.reg"
reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LITSSVC "$PSScriptRoot\BGT\ITSSettings.reg"
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol" "$PSScriptRoot\BGT\WindowsProtocol.reg"


# ***********************************************************************************************
# Get all users BG showing info
WriteLog "-----------> Get all users BG showing info, by using ProfileList of HKEY_USERS"
$pathUserProfile = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
if( -not(Test-Path $pathUserProfile) ){WriteLog ("Error -- FileNoFound: " + $pathUserProfile)}

Get-ItemProperty -Path $pathUserProfile | ForEach-Object { 
	$SidStr = $_ | Select-Object -Property PSChildName -Unique|%{"{0}" -f $_.PSChildName.ToString()} 
	$ShowTBKeys = "Registry::HKEY_USERS\$SidStr\Software\Lenovo\BatteryGauge"
	if( -not(Test-Path $ShowTBKeys) )
	{
		WriteLog ("Error -- FileNoFound: " + $ShowTBKeys)
	}
	else
	{
		$ShowTBDetails = Get-ItemProperty -Path $ShowTBKeys
		$ShowTBDetailsToLog = "ShowInTaskbar\$SidStr" + ": ShowInTaskbar=" + $ShowTBDetails.ShowInTaskbar + ", PluginInvokeIndex=" + $ShowTBDetails.PluginInvokeIndex + ", LastHeartbeatTimeEx=" + $ShowTBDetails.LastHeartbeatTimeEx
		WriteLog $ShowTBDetailsToLog
	}
}



# ***********************************************************************************************
# Test simulation
# -----------------------------------------------------------------------------------------------

# ----------- Create log path of QuickSetting
WriteLog "-----------> Create log path of QuickSetting"
$pathQuickSettingLog = "$env:UserProfile\AppData\LocalLow\Lenovo\batterygauge\log"
New-Item $pathQuickSettingLog -Force -type Directory
if( -not(Test-Path $pathQuickSettingLog) ){WriteLog ("Error -- FileNoFound: " + $pathQuickSettingLog)}

# ----------- Run QuickSettingEx.exe to generate log
WriteLog "-----------> Run QuickSettingEx.exe to generate log"
$pathQuickSettingExe = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\x64\QuickSettingEx.exe"
if( -not(Test-Path $pathQuickSettingExe) )
{$pathQuickSettingExe = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\x86\QuickSettingEx.exe"}
if( -not(Test-Path $pathQuickSettingExe) ){WriteLog ("Error -- FileNoFound: " + $pathQuickSettingExe)}

if (Test-Path "$pathQuickSettingExe")
{
	Start-Process $pathQuickSettingExe -WindowStyle Hidden
	
	Write-Host  "Please wait some seconds..."
	Start-Sleep -Milliseconds 5000
	Start-Process -NoNewWindow -Wait -FilePath taskkill.exe -ArgumentList "/F /T /IM QuickSettingEx.exe"
}

# ----------- Get file version 
$BGDllPath = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\x64\LenovoBatteryGaugePackage.dll"
$TBPDllPath = "$env:ProgramData\Lenovo\ImController\Plugins\ThinkBatteryPlugin\x86\ThinkBatteryPlugin.dll"
$INPDllPath = "$env:ProgramData\Lenovo\ImController\Plugins\IdeaNotebookPlugin\x64\IdeaNotebookPlugin.dll"

$QSVersion = ""
if (Test-Path "$pathQuickSettingExe")
{$QSVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$pathQuickSettingExe").FileVersion}

$BGDllVersion = ""
if (Test-Path "$BGDllPath")
{$BGDllVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$BGDllPath").FileVersion}

$TBPDllVersion = ""
if (Test-Path "$TBPDllPath")
{$TBPDllVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$TBPDllPath").FileVersion}

$INPDllVersion = ""
if (Test-Path "$INPDllPath")
{$INPDllVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$INPDllPath").FileVersion}

WriteLog "===> FileVersion: QuickSettingEx-$QSVersion, LenovoBatteryGaugePackage-$BGDllVersion, ThinkBatteryPlugin-$TBPDllVersion, IdeaNotebookPlugin-$INPDllVersion"


# ----------- Copy log files of QuickSetting, dmp and BGDLL
WriteLog "-----------> Copy log files of QuickSetting, dmp and BGDLL"
if (Test-Path "$pathQuickSettingLog\quickpanel.log")
{
	Copy-Item "$pathQuickSettingLog\quickpanel.log" "$PSScriptRoot\BGT\Before_quickpanel.log" -Force

	WriteLog "-----------> Delete log folder of QuickSetting, dmp and BGDLL"
	Remove-Item -Recurse -Force $pathQuickSettingLog 
}

$pathQuickSettingDump = "$env:UserProfile\AppData\LocalLow\Lenovo\batterygauge\dump"
WriteLog "-----------> Copy log files of QuickSetting dump files"
if (Test-Path $pathQuickSettingDump)
{
	Copy-Item "$pathQuickSettingDump\*" "$PSScriptRoot\BGT\" -Force -Recurse

	WriteLog "-----------> Delete log folder of QuickSetting dump files"
	Remove-Item -Recurse -Force "$pathQuickSettingDump\*" 
}
# Get plugins related info--after Install BG. --end
# ***********************************************************************************************
# ***********************************************************************************************







# ***********************************************************************************************
# ***********************************************************************************************
# Install BG
if (-not(Test-Path "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_"))
{
	WriteLog "New-Item PathPackageDirDest -type directory"
	New-Item "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_\" -type directory

	# Copy source files to destination directory
	WriteLog "Copy new version package contents to package folder, and give neccessary privileage"
	Copy-Item "$PSScriptRoot\LenovoBatteryGaugePackage\*" "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_\" -force -recurse
	if($? -ne $true)
	{
		WriteLog "Copy-Item error... error code is: $LastExitCode"
	}
}

if (Test-Path "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_\x64\Install.ps1")
{
	Start-Process -NoNewWindow -Wait -FilePath "$psHome\powershell.exe"  -ArgumentList "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_\x64\Install.ps1"
}




# ***********************************************************************************************
# ***********************************************************************************************
# Get plugins related info--after Install BG. --begin
# ***********************************************************************************************
# List all files of ImController-Plugins
#WriteLog "-----------> List all files of ImController-Plugins"
#powershell tree "$env:ProgramData\Lenovo\ImController\Plugins" /F >"$PSScriptRoot\BGT\After_Details_ImControllerPlugins.txt"
#if (Test-Path "$env:ProgramData\Lenovo\ImController\Plugins\")
#{
#	powershell ls "$env:ProgramData\Lenovo\ImController\Plugins\" -recurse |
#		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\After_Details_ImControllerPluginsEx.txt"
	
#	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\" -Recurse | 
#		Get-Acl | Out-File "$PSScriptRoot\BGT\After_Details_ImControllerPluginsACL1.txt"

#	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\" -Recurse | 
#		Get-Acl | Format-List | Out-File "$PSScriptRoot\BGT\After_Details_ImControllerPluginsACL2.txt"
#}

# ***********************************************************************************************
# List all details of BatteryGauge folder, including temperary folder
WriteLog "-----------> List all details of BatteryGauge folder"
if (Test-Path "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\")
{
	powershell ls "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\After_Details_LenovoBatteryGaugePackage.txt"

	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\" -Recurse | 
		Get-Acl | Out-File "$PSScriptRoot\BGT\After_Details_LenovoBatteryGaugePackageACL1.txt"

	Get-ChildItem "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\" -Recurse | 
		Get-Acl | Format-List | Out-File "$PSScriptRoot\BGT\After_Details_LenovoBatteryGaugePackageACL2.txt"
}
else
{WriteLog ("Error -- FileNoFound: " + "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\")}

# IMC
$IMCService = Get-Service -Name 'ImControllerService'
if($IMCService -ne $null)
{
	$IMCCanStop = $IMCService.CanStop
	$IMCCanPause = $IMCService.CanPauseAndContinue
	WriteLog "ImControllerStatus status: IMCCanStop=$IMCCanStop, IMCCanPause=$IMCCanPause"
}

if (Test-Path "$env:SystemRoot\Lenovo\ImController\Service\")
{
	powershell ls "$env:SystemRoot\Lenovo\ImController\Service\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\After_ImController.txt"
}

# VS
$VSService = Get-Service -Name 'LenovoVantageService'
if($VSService -ne $null)
{
	$VSCanStop = $VSService.CanStop
	$VSCanPause = $VSService.CanPauseAndContinue
	WriteLog "LenovoVantageService status: VSCanStop=$VSCanStop, VSCanPause=$VSCanPause"
}

if (Test-Path "C:\Program Files (x86)\Lenovo\VantageService\")
{
	powershell ls "C:\Program Files (x86)\Lenovo\VantageService\" -recurse |
		Select-Object Name, Length, LastWriteTime | Out-File "$PSScriptRoot\BGT\After_VantageService.txt"
}

# reg
reg export HKEY_CURRENT_USER\Software\Lenovo "$PSScriptRoot\BGT\After_HKCULenovo.reg"
reg export HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System "$PSScriptRoot\BGT\After_HKLMSystem.reg"
reg export HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lenovo\ImController\Packages\LenovoBatteryGaugePackage "$PSScriptRoot\BGT\After_BGInstallHistory.reg"


# ***********************************************************************************************
# Get all users BG showing info
WriteLog "-----------> Get all users BG showing info, by using ProfileList of HKEY_USERS"
$pathUserProfile = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
if( -not(Test-Path $pathUserProfile) ){WriteLog ("Error -- FileNoFound: " + $pathUserProfile)}

Get-ItemProperty -Path $pathUserProfile | ForEach-Object { 
	$SidStr = $_ | Select-Object -Property PSChildName -Unique|%{"{0}" -f $_.PSChildName.ToString()} 
	$ShowTBKeys = "Registry::HKEY_USERS\$SidStr\Software\Lenovo\BatteryGauge"
	if( -not(Test-Path $ShowTBKeys) )
	{
		WriteLog ("Error -- FileNoFound: " + $ShowTBKeys)
	}
	else
	{
		$ShowTBDetails = Get-ItemProperty -Path $ShowTBKeys
		$ShowTBDetailsToLog = "ShowInTaskbar\$SidStr" + ": ShowInTaskbar=" + $ShowTBDetails.ShowInTaskbar + ", PluginInvokeIndex=" + $ShowTBDetails.PluginInvokeIndex + ", LastHeartbeatTimeEx=" + $ShowTBDetails.LastHeartbeatTimeEx
		WriteLog $ShowTBDetailsToLog
	}
}



# ***********************************************************************************************
# Test simulation
# -----------------------------------------------------------------------------------------------

# ----------- Create log path of QuickSetting
WriteLog "-----------> Create log path of QuickSetting"
$pathQuickSettingLog = "$env:UserProfile\AppData\LocalLow\Lenovo\batterygauge\log"
New-Item $pathQuickSettingLog -Force -type Directory
if( -not(Test-Path $pathQuickSettingLog) ){WriteLog ("Error -- FileNoFound: " + $pathQuickSettingLog)}

# ----------- Run QuickSettingEx.exe to generate log
WriteLog "-----------> Run QuickSettingEx.exe to generate log"
$pathQuickSettingExe = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\x64\QuickSettingEx.exe"
if( -not(Test-Path $pathQuickSettingExe) )
{$pathQuickSettingExe = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\x86\QuickSettingEx.exe"}
if( -not(Test-Path $pathQuickSettingExe) ){WriteLog ("Error -- FileNoFound: " + $pathQuickSettingExe)}

if (Test-Path "$pathQuickSettingExe")
{
	Start-Process $pathQuickSettingExe -WindowStyle Hidden
	
	Write-Host  "Please wait some seconds..."
	Start-Sleep -Milliseconds 5000
	Start-Process -NoNewWindow -Wait -FilePath taskkill.exe -ArgumentList "/F /T /IM QuickSettingEx.exe"
}


# ----------- Copy log files of QuickSetting, dmp and BGDLL
WriteLog "-----------> Copy log files of QuickSetting, dmp and BGDLL"
if (Test-Path "$pathQuickSettingLog\quickpanel.log")
{
	Copy-Item "$pathQuickSettingLog\quickpanel.log" "$PSScriptRoot\BGT\After_quickpanel.log" -Force

	WriteLog "-----------> Delete log folder of QuickSetting, dmp and BGDLL"
	Remove-Item -Recurse -Force $pathQuickSettingLog 
}

# ***********************************************************************************************
# Get plugins related info--after Install BG. --end
# ***********************************************************************************************
# ***********************************************************************************************







# ***********************************************************************************************
# Get Vantage install info
if (Test-Path "$env:ProgramData\Lenovo\ImController\shared\AppsAndTags.xml")
{
	Copy-Item "$env:ProgramData\Lenovo\ImController\shared\AppsAndTags.xml"  "$PSScriptRoot\BGT\AppsAndTags.xml" -Force
}

if (Test-Path "$env:ProgramData\Lenovo\ImController\shared\MachineInformation.xml")
{
	Copy-Item "$env:ProgramData\Lenovo\ImController\shared\MachineInformation.xml"  "$PSScriptRoot\BGT\MachineInformation.xml" -Force
}

if (Test-Path "$env:ProgramData\Lenovo\ImController\ImControllerSubscription.xml")
{
	Copy-Item "$env:ProgramData\Lenovo\ImController\ImControllerSubscription.xml"  "$PSScriptRoot\BGT\ImControllerSubscription.xml" -Force
}

# ----------- Update to new version of BatteryGauge
WriteLog "-----------> Update to new version of BatteryGauge"
Write-Host  "Please wait for updating..."

# -----------------------------------------------------------------------------------------------
# Test simulation -end
# ***********************************************************************************************


# ***********************************************************************************************
# Zip all BGTFiles
Function ZipBGTFiles
{
    param([PSObject[]]$zpInput)
	
	$pathZipSource = "$PSScriptRoot\BGT"
	$pathZipDestFile = "$PSScriptRoot\BGT.zip"
	
	[System.Reflection.Assembly]::Load("WindowsBase, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")
	if (Test-Path($pathZipDestFile)) {Remove-Item $pathZipDestFile}
	
	$sourceDirectory = New-Object System.IO.DirectoryInfo($pathZipSource);
	$sourceFiles = $sourceDirectory.GetFiles()
	if($sourceFiles.Count -ne 0)
	{
		$pkg=[System.IO.Packaging.ZipPackage]::Open($pathZipDestFile, [System.IO.FileMode]"OpenOrCreate", [System.IO.FileAccess]"ReadWrite")
		
		# add file
		ForEach ($singleFile In $sourceFiles)
		{
			$uriString = "/" + $singleFile.Name
			$partName = New-Object System.Uri($uriString, [System.UriKind]"Relative")
			$pkgPart = $pkg.CreatePart($partName, "application/zip", [System.IO.Packaging.CompressionOption]"Maximum")
			$bytes = [System.IO.File]::ReadAllBytes($singleFile.FullName)
			$stream = $pkgPart.GetStream()
			$stream.Seek(0, [System.IO.SeekOrigin]"Begin");
			$stream.Write($bytes, 0, $bytes.Length)
			$stream.Close()
			Remove-Item $singleFile.FullName
		}
		
		$pkg.Close()
	}
	
	# remove test folder
	$sourceFiles = $sourceDirectory.GetFiles()
	if($sourceFiles.Count -eq 0){Remove-Item -Force $pathZipSource}
}

# Restart ITS service if exist
if (($ITSService -ne $null) -and (Test-Path "$ITSSvcExe"))
{
	WriteLog "ITS Service ---> try to start service...."
	Start-Service $ITSService.Name
	Start-Sleep -Milliseconds 1000
}
WriteLog "-----------> ZipBGTFiles"	
ZipBGTFiles ""

powershell "C:\Windows\System32\rundll32.exe" "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\x64\LenovoBatteryGaugePackage.dll,ShowBatteryGauge"


# ***********************************************************************************************
# Del Log swith in registry
Del "HKLM:\SOFTWARE\WOW6432Node\Lenovo\Modern\Logs\" -Recurse -Force

# ***********************************************************************************************
# Successfully and exit
Write-Host  "-----------> Successfully!!  Press any key to exit..."
Start-Sleep -Milliseconds 1000
Exit
