trap {"An error trapped..."}

# ::***********************************************************************************************
# :: Definition-1: Check bitness of OS, process, package, guid of old version
# ::***********************************************************************************************
$OS_BITNESS=32
if([Environment]::Is64BitOperatingSystem -eq $True) {
$OS_BITNESS=64
}

$PS_BITNESS=32
if([Environment]::Is64BitProcess -eq $True) {
$PS_BITNESS=64
}

$PK_BITNESS=32
if(($PSScriptRoot.ToLower().Contains("x64".ToLower())) -eq $True) {
$PK_BITNESS=64
}

$arch="x86"
if ($OS_BITNESS -eq 64) {
$arch="x64"
}

$PRODCODE64="{CBEDEC16-C4F5-4255-99E4-5884EFEDD1BC}"
$PRODCODE32="{01DBFF2E-73FD-4CC3-98CE-B39260D80D8C}"
$PRODCODE64_OLD="{B8D3ED8D-A295-44C2-8AE1-56823D44AD1F}"
$PRODCODE32_OLD="{840DE7EE-4816-4402-BEE4-80517B3233A3}"


# ::***********************************************************************************************
# :: Definition-2: common variables and functions
# ::***********************************************************************************************
$PackageName = "LenovoBatteryGaugePackage"
$PathPackageDirDest = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage"
$PathPackageDirSource = "$env:ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage_"

# ::***********************************************************************************************
# :: Definition: Write-Log
$LogFileName = ("$PackageName" + ".Install." + (Get-Date -Format "-yyyy_MM_dd-HH-mm-ss") + ".txt")
$PathLogFile = "$env:ProgramData\Lenovo\Modern\Logs\$LogFileName"

[bool]$EnableLogging = $false
try { $EnableLogging = ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Lenovo\Modern\Logs" -Name "ImController.Service") -eq 0 ) } catch{}

if($EnableLogging -and ( -not(Test-Path $PathLogFile))) {
	New-Item -Path (Split-Path $PathLogFile) -Name (Split-Path $PathLogFile -leaf) -ItemType File -force
}

$PSDefaultParameterValues["Write-Log:pathToLogFile"]=$PathLogFile
$PSDefaultParameterValues["Write-Log:enableLogging"]=$EnableLogging

Function Write-Log
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

	  	Out-File -InputObject $objTS -FilePath $pathToLogFile -Encoding unicode -Append -Width 200
    }
}

Function PrintDestPackageDetails
{
	if($EnableLogging)
	{
		if(Test-Path "$PathPackageDirDest\$arch")
		{
			Get-ChildItem -Path "$PathPackageDirDest\$arch" | Select-Object Name, LastWriteTime, Length | Out-File  $PathLogFile -Encoding unicode -Append
		}
		else
		{
			Write-Log "The dest package dir does not exist($PathPackageDirDest\$arch)"
		}
	}
}


Function UninstallMsi($prodCode)
{
	$uninstallString = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$prodCode" -Name "UninstallString" -ErrorAction SilentlyContinue).UninstallString
	if (($UninstallString -ne $null) -and ($uninstallString.Length -ne 0)) {
		Write-Log "start uninstall msi package for PRODCODE $prodCode"
		$MSIEXECPATH = "$env:SystemRoot\System32\MsiExec.exe"
		Write-Log "Start-Process -NoNewWindow -Wait -FilePath $MSIEXECPATH `"/X$prodCode /quiet /noreboot`""
		Start-Process -NoNewWindow -Wait -FilePath $MSIEXECPATH "/X$prodCode /quiet /noreboot" *>&1 | Write-Log
	}
	else
	{
		Write-Log "cannot find uninstall entry for program PRODCODE $prodCode"
	}
}

Function GetCurrentActiveUserSID
{
	$activeUser = Get-WmiObject Win32_ComputerSystem -ComputerName $env:computername -EA stop | Select UserName -Unique|%{"{0}" -f $_.UserName.ToString().Split('\')[1]}
	$objUser = New-Object System.Security.Principal.NTAccount("$activeUser")
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
	$strSID.Value
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


# ::***********************************************************************************************
# :: Definition: BatteryGaugeIconControl
$applicationName = "$env:SystemRoot\system32\rundll32.exe"
$ShowBg = "ShowBatteryGauge"
$HideBg = "HideBatteryGauge"
$UnloadBg = "UnloadBatteryGaugeFromExplorer"
$InstallFileName = "Install.ps1"
$UninstallFileName = "Uninstall.ps1"

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

# ::***********************************************************************************************
# :: Definition: expand shortcut file
$PathShortCutDir = "$PSScriptRoot\.."
if( -not(Test-Path $PathShortCutDir) ) {
	$PathShortCutDir = $PathPackageDirDest
	if($true -eq ((($PSCommandPath).ToUpper()).Contains("LENOVOBATTERYGAUGEPACKAGE_"))){
		$PathShortCutDir = $PathPackageDirSource
	}
}

Function Expand-EnvironmentVariablesForLnkFile
{
    param([string]$modulePlatform, [string]$moduleFunction)

	if( -not(Test-Path "$PathShortCutDir\$modulePlatform") ) {
		return
	}

    $shortCutFile = "$PathShortCutDir\$modulePlatform\$moduleFunction" + ".lnk"
	$argumentsList = "$PathPackageDirDest\$modulePlatform\LenovoBatteryGaugePackage.dll," + $moduleFunction
	$workingDir = "$PathPackageDirDest\$modulePlatform\"

    $wScriptShell = New-Object -ComObject WScript.Shell 
    $shortCut = $wScriptShell.CreateShortcut($shortCutFile) 
    $shortCut.TargetPath = [Environment]::ExpandEnvironmentVariables($applicationName)
    $shortCut.Arguments = [Environment]::ExpandEnvironmentVariables($argumentsList)
    $shortCut.WorkingDirectory = [Environment]::ExpandEnvironmentVariables($workingDir)
    $shortCut.Save() 
}

Function Expand-EnvironmentVariablesForLnkFileEx
{
	param([string]$moduleFunction)

	Expand-EnvironmentVariablesForLnkFile "x86" $moduleFunction
	Expand-EnvironmentVariablesForLnkFile "x64" $moduleFunction
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


# BG should be excluded when device satisfies: {China + Lenovo/Idea brand + PCManager installed}
Function BatteryGaugeShouldBeExclude
{
    $IsExclude = $False

    $miVantagePath = "$env:LOCALAPPDATA\Packages\E046963F.LenovoCompanion_k1h2ywk1493x8"
	$miVantageMVPPath = "$env:LOCALAPPDATA\Packages\E046963F.LenovoCompanionBeta_k1h2ywk1493x8"
    $miLEPath = "$env:LOCALAPPDATA\Packages\E046963F.LenovoSettingsforEnterprise_k1h2ywk1493x8"
    $IsInstallVantageLE = ((Test-Path $miVantagePath) -or (Test-Path $miVantageMVPPath) -or (Test-Path $miLEPath))
    if(-not($IsInstallVantageLE))
    {
        $miXmlFilePath = "$env:ProgramData\Lenovo\ImController\shared\MachineInformation.xml"

        $miXmlData = [xml](Get-Content $miXmlFilePath)
        $miCountry = ($miXmlData.MachineInformation.Country).ToLower()
        if($miCountry.Contains("cn"))
        {
            $miBrand = ($miXmlData.MachineInformation.Brand).ToLower()            
            $IsExclude = (($miBrand.Contains("idea")) -or ($miBrand.Contains("lenovo")))
        }

    }
    
    if($IsExclude)
    {
        #Is PCManager installed?
		$PcManagerRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lenovo\PcManager'
		$IsExclude = (Test-Path "Registry::$PcManagerRegPath")
    }

    return $IsExclude
}

# BG is installed?
Function BatteryGaugeIsInstalled
{
    $IsInstalled = $False
	$BGRegistryPath = 'HKEY_CLASSES_ROOT\CLSID\{E303DE81-073F-438A-B0D3-11C27526F607}'
	if(Test-Path "Registry::$BGRegistryPath")
	{
		$IsInstalled = $True
	}

    return $IsInstalled
}

# BG is pinned in taskbar?
Function IsBatteryGaugePinInTaskbar
{
	$IsBGPinned = 0

	$BgTaskList = tasklist /M "LenovoBatteryGaugePackage.dll"
	$ExplorerLike = $BgTaskList -like "explorer*"
	if($ExplorerLike -eq $true)
	{  
		$IsBGPinned = 1  
	}
	elseif($ExplorerLike -ne $false)
	{
		$BgInExplorer = (($ExplorerLike).ToLower()).Contains("explorer")
		if($BgInExplorer -eq $true)
		{  
			$IsBGPinned = 1  
		}
	}

	return $IsBGPinned
}



$RegSvr32Path = "$env:SystemRoot\System32\regsvr32.exe"
$RegAsmPath = "$PathPackageDirDest\$arch\RegAsm.exe"

# ::***********************************************************************************************
# :: Register new Lenovo Battery Gauge: PluginsContract.dll, LenovoBatteryGaugePackage.dll
# ::***********************************************************************************************
Function RegisterNewBatteryGauge
{
	# check directory first!!!!
	#Start-Process -NoNewWindow -Wait -FilePath $RegAsmPath -ArgumentList "/silent $PathPackageDirDest\$arch\PluginsContract.dll"
	powershell $RegAsmPath "/silent $PathPackageDirDest\$arch\PluginsContract.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegAsmPath `"/silent $PathPackageDirDest\$arch\PluginsContract.dll`""
	}

	#Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList "/s $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	powershell $RegSvr32Path "/s $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegSvr32Path `"/s $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll`""
	}
}


# ::***********************************************************************************************
# Unregister new Lenovo Battery Gauge: LenovoBatteryGaugePackage.dll, PluginsContract.dll
# ::***********************************************************************************************
Function UnregisterNewBatteryGauge
{
	# check directory first!!!!
	#Start-Process -NoNewWindow -Wait -FilePath $RegSvr32Path -ArgumentList "/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	powershell $RegSvr32Path "/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegSvr32Path `"/s -u $PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll`""
	}

	#Start-Process -NoNewWindow -Wait -FilePath $RegAsmPath -ArgumentList "/silent /u $PathPackageDirDest\$arch\PluginsContract.dll"
	powershell $RegAsmPath "/silent /u $PathPackageDirDest\$arch\PluginsContract.dll"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, powershell $RegAsmPath `"/silent /u $PathPackageDirDest\$arch\PluginsContract.dll`""
	}
}


# ::***********************************************************************************************
# Uninstall old Lenovo Battery Gauge(which install by MSI). 
# Notice: It does not exist in most Win10 devices now. So handle it with low priority.
# ::***********************************************************************************************
Function UninstallMsiOldBatteryGauge
{
	if (Get-Variable ProdCode64 -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode64)
	}
	if (Get-Variable ProdCode32 -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode32)
	}
	if (Get-Variable ProdCode64_OLD -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode64_OLD)
	}
	if (Get-Variable ProdCode32_OLD -ErrorAction SilentlyContinue) {
		UninstallMsi($ProdCode32_OLD)
	}
}


# ::***********************************************************************************************
# Register exe MaintenanceTask 
# ::***********************************************************************************************
Function RegisterMaintenanceTask
{
	# Delete ps1 MaintenanceTask if exist. 
	$SchTasksPath = "$env:SystemRoot\System32\schtasks.exe"
	#if( Test-Path -Path "$PathPackageDirDest\data\Maintenance.ps1" -PathType Leaf )
	#{
		powershell $SchTasksPath /Delete /TN "\Lenovo\BatteryGauge\BatteryGaugeMaintenance" /F
		if($? -eq $true)
		{
			if( Test-Path -Path "$PathPackageDirDest\data\Maintenance.ps1" -PathType Leaf )
			{
				Remove-Item -Path "$PathPackageDirDest\data\Maintenance.ps1"
			}
		}
	#}

	# Register exe MaintenanceTask. check directory first!!!!
	$PathMaintenanceTask = $PathPackageDirDest
	if ($PSScriptRoot -ne "$PathPackageDirDest\$arch")
	{$PathMaintenanceTask = $PathPackageDirSource}

	powershell $SchTasksPath /Create /XML "$PathMaintenanceTask\data\MaintenanceTask.xml" /TN "\Lenovo\BatteryGauge\BatteryGaugeMaintenance"
	if($? -ne $true)
	{
		Write-Log "ReturnCode=$LastExitCode, $SchTasksPath /Create /XML `"$PathMaintenanceTask\data\MaintenanceTask.xml`" /TN `"\Lenovo\BatteryGauge\BatteryGaugeMaintenance`""
	}
}


# ::***********************************************************************************************
# :: Rename to ensure file update successful
# ::***********************************************************************************************
Function RenameFileForUpdate
{
	param([string]$fileName)

	$fileNameBK = $fileName + "_bk"
	if( Test-Path -Path "$PathPackageDirDest\x86\$fileNameBK" -PathType Leaf)
	{
		Remove-Item -Path "$PathPackageDirDest\x86\$fileNameBK" -Force
	}
	Rename-Item -Path "$PathPackageDirDest\x86\$fileName" -NewName "$fileNameBK"

	if( Test-Path -Path "$PathPackageDirDest\x64\$fileNameBK" -PathType Leaf)
	{
		Remove-Item -Path "$PathPackageDirDest\x64\$fileNameBK" -Force
	}	
	Rename-Item -Path "$PathPackageDirDest\x64\$fileName" -NewName "$fileNameBK"
}

Function RenameFileBack
{
	param([string]$fileNameSrc)

	$fileNameSrcBK = $fileNameSrc + "_bk"
	if( -not(Test-Path -Path "$PathPackageDirDest\x86\$fileNameSrc" -PathType Leaf) )
	{
		Rename-Item -Path "$PathPackageDirDest\x86\$fileNameSrcBK" -NewName "$fileNameSrc"
	}

	if( -not(Test-Path -Path "$PathPackageDirDest\x64\$fileNameSrc" -PathType Leaf) )
	{
		Rename-Item -Path "$PathPackageDirDest\x64\$fileNameSrcBK" -NewName "$fileNameSrc"
	}
}

# ::***********************************************************************************************
# :: use "Trap" to handle terminating error( to force script running )
# ::***********************************************************************************************
trap 
{
	"An error trapped"
	$TrapError = $_.Exception
	$TrapErrorMsg = $TrapError.Message 
	$TrapLine = $_.InvocationInfo.ScriptLineNumber	
	Write-Log "Caught exception( trapped error ) at line[$TrapLine]: Msg= $TrapErrorMsg"
}

# ::***********************************************************************************************
# :: Begin installation
# ::
# :: 
# ::***********************************************************************************************

Write-Log "Below logs come from: $PSCommandPath"

Write-Log "Register MaintenanceTask if necessary"
RegisterMaintenanceTask


# BG should be excluded from this device?
$BgInstalled = BatteryGaugeIsInstalled
if(BatteryGaugeShouldBeExclude)
{
	Write-Log "Exit... BatteryGauge should be excluded from device whom brand is Lenovo or Idea and PCManager has been installed(Geo = China(PRC))"

	# Delete BG if it has been installed
	if($BgInstalled -eq $True)
	{
		if (Test-Path "$PathPackageDirDest\$arch\$UninstallFileName")
		{
			Write-Log "Begin to uninstall BatteryGauge in the device which has installed PCManager...."
			$PSPATH="$env:SystemRoot\System32\WindowsPowerShell\v1.0\PowerShell.exe"
			Write-Log "Start-Process -NoNewWindow -Wait -FilePath $PSPATH -ArgumentList `"$PathPackageDirDest\$arch\$UninstallFileName`""
			Start-Process -NoNewWindow -Wait -FilePath $PSPATH -ArgumentList "$PathPackageDirDest\$arch\$UninstallFileName" *>&1 | Write-Log
		}
	}
		
	Exit
}

# Does package match OS bitness???
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
# Expand shortcut with absolute path for BG control
# ::***********************************************************************************************
Expand-EnvironmentVariablesForLnkFileEx "ShowBatteryGauge"
Expand-EnvironmentVariablesForLnkFileEx "HideBatteryGauge"
Expand-EnvironmentVariablesForLnkFileEx "UnpinFromTaskbar"
Expand-EnvironmentVariablesForLnkFileEx "UnloadBatteryGaugeFromExplorer"
Expand-EnvironmentVariablesForLnkFileEx "SetMenuItemNameofBatteryGauge"
Expand-EnvironmentVariablesForLnkFileEx "UpdateBatteryGaugeToastInfo"
Expand-EnvironmentVariablesForLnkFileEx "LaunchPinVantageToolbarToast"

# ::***********************************************************************************************
# :: [Kill active BG processes]:
# ::  QuickSetting.exe,QuickSettingEx.exe,HeartbeatMetrics.exe,SetThinkTouchPad.exe....]
# ::***********************************************************************************************
#StopBGProcessDirectly


# ::***********************************************************************************************
# :: [Uninstall old Lenovo Battery Gauge ]
# ::***********************************************************************************************
Write-Log "Uninstall old Lenovo Battery Gauge(which install by MSI). It might not exist"
UninstallMsiOldBatteryGauge


#::***********************************************************************************************
#:: [Check whether pinned battery gauge to taskbar previously]
#::***********************************************************************************************
$Pinned = 0
$SID = GetCurrentActiveUserSID	
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$BgPinReg = (Get-ItemProperty -Path HKU:$SID\SOFTWARE\Lenovo\BatteryGauge -Name "ShowInTaskbar" -ErrorAction SilentlyContinue).ShowInTaskbar
	
## Is BG pinned ? Check it in taskbar
$BgPinTaskbar = IsBatteryGaugePinInTaskbar	
if(($BgPinReg -eq 1) -or ($BgPinTaskbar -eq 1))
{
	$Pinned = 1
}

Write-Log "The BatteryGauge current display status: BgPinReg = $BgPinReg, BgPinTaskbar=$BgPinTaskbar"
#Remove-PSDrive -Name HKU


# ::**************************************************************************************************
# :: This section run only when current scripts running in package folder
# ::    1. Call uninstall.ps1 in the package folder if it has been install in this PC, and then delete package folder
# ::    2. Create package folder and copy content to it
# ::    3. Call install.ps1 in the package folder
# :: 
# ::**************************************************************************************************
if ($PSScriptRoot -ne "$PathPackageDirDest\$arch")
{
	trap {"An error trapped 2..."}

	Write-Log "Details of dest package info(old version)-------------------------"
	PrintDestPackageDetails
	
	#::***********************************************************************************************
	#:: [Uninstall the old version]
	#::***********************************************************************************************
	if (Test-Path "$PathPackageDirDest\$arch\$UninstallFileName")
	{
		trap {"An error trapped 3..."}

		Write-Log "Uninstall old version directly"
		Write-Log "Push-Location `"$PathPackageDirDest\$arch\`""
		Push-Location "$PathPackageDirDest\$arch\"
		
		Write-Log "Unload BatteryGauge from explorer"
		BatteryGaugeIconControlEx($UnloadBg)
		
		if ($Pinned -eq 1)
		{
			Write-Log "Keep BG status in registry if necessary, PinStatus=$Pinned"
			#$SID = GetCurrentActiveUserSID
			
			#New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
			New-ItemProperty -Path HKU:$SID\SOFTWARE\Lenovo\BatteryGauge -Name "ShowInTaskbar" -Value $Pinned -PropertyType DWORD -Force		
			#Remove-PSDrive -Name HKU
		}

		Write-Log "Unregister BatteryGauge related components"
		UnregisterNewBatteryGauge

		Write-Log "Pop-Location"
		Pop-location
		
		Write-Log "Uninstall completely! Kill related BG processes"
		StopBGProcessDirectly

		# try again
		StopProcessByTaskkill
		# don't remove old version files!!!
		#Write-Log "Remove-Item -Recurse -Force `"$PathPackageDirDest`""
		#Remove-Item -Recurse -Force "$PathPackageDirDest"
	}

	## ::************************************************************************************************
	## :: [Rename the LenovoBatteryGaugePackage.dll file if this file haven't been removed. There was   ]
	## :: [issue which will lead this dll cannot unload from explorer due to in-use, then cannot replace]
	## :: [Can remove this operation from next version, since already fixed the in-use issue in the dll ]
	## ::************************************************************************************************
	if(Test-Path -Path "$PathPackageDirDest\$arch\LenovoBatteryGaugePackage.dll" -PathType Leaf)
	{
		$BgPinTaskbar = IsBatteryGaugePinInTaskbar	
		Write-Log "Some files might still exist, such as BG main dll. Rename it to avoid copy files failure"
		RenameFileForUpdate "LenovoBatteryGaugePackage.dll"
		RenameFileForUpdate "Lenovo.AssemblyValidation.Native.dll"
		RenameFileForUpdate "Lenovo.CertificateValidation.dll"
		RenameFileForUpdate "QuickSettingEx.exe"
		RenameFileForUpdate "QSHelper.exe"
		RenameFileForUpdate "HeartbeatMetrics.exe"
		RenameFileForUpdate "IdeaIntelligentCoolingMetrics.exe"
		RenameFileForUpdate "Lenovo.ImController.EventLogging.dll"
		RenameFileForUpdate "Lenovo.Modern.CoreTypes.dll"
		RenameFileForUpdate "Lenovo.Modern.ImController.ImClient.dll"
		RenameFileForUpdate "Lenovo.Modern.Utilities.dll"
		RenameFileForUpdate "Newtonsoft.Json.dll"


		if($BgPinTaskbar -eq 1)
		{
			Start-Sleep -Milliseconds 1200
		}
	}
	

	#::***********************************************************************************************
	#:: [Copy new version to dest directory]
	#::***********************************************************************************************
	Write-Log "Make package folder for new version"
	Write-Log "New-Item `"$PathPackageDirDest\`" -type directory"
	New-Item "$PathPackageDirDest\" -type directory

	# Copy source files to destination directory
	Write-Log "Copy new version package contents to package folder, and give neccessary privileage"
	Write-Log "Copy-Item `"$PSScriptRoot\..\*`" `"$PathPackageDirDest\`" -force -recurse"
	Copy-Item "$PSScriptRoot\..\*" "$PathPackageDirDest\" -force -recurse
	if($? -ne $true)
	{
		Write-Log "Copy-Item error... error code is: $LastExitCode"
	}

	# Preserve old version again, if copy failed or the new source files was deleted unexpectedly
	Write-Log "Preserve old version again, if copy failed"
	RenameFileBack "LenovoBatteryGaugePackage.dll"
	RenameFileBack "Lenovo.AssemblyValidation.Native.dll"
	RenameFileBack "Lenovo.CertificateValidation.dll"
	RenameFileBack "QuickSettingEx.exe"
	RenameFileBack "QSHelper.exe"
	RenameFileBack "HeartbeatMetrics.exe"
	RenameFileBack "IdeaIntelligentCoolingMetrics.exe"
	RenameFileBack "Lenovo.ImController.EventLogging.dll"
	RenameFileBack "Lenovo.Modern.CoreTypes.dll"
	RenameFileBack "Lenovo.Modern.ImController.ImClient.dll"
	RenameFileBack "Lenovo.Modern.Utilities.dll"
	RenameFileBack "Newtonsoft.Json.dll"


	Write-Log "Install new version directly"
	Write-Log "Push-Location `"$PathPackageDirDest\$arch\`""
	Push-Location "$PathPackageDirDest\$arch\"
	
	Write-Log "Register BatteryGauge related components"
	RegisterNewBatteryGauge

	Write-Log "Show BatteryGauge if neccessary: PinStatus = $Pinned"
	if ($Pinned -eq 1)
	{
		BatteryGaugeIconControlEx($ShowBg)
	}

	Write-Log "Pop-location"
	Pop-location
	
	Write-Log "Install completely! Remove the temporary install package folder"
	Write-Log "Remove-Item -Recurse -Force `"$PSScriptRoot\..`""
	Remove-Item -Recurse -Force "$PSScriptRoot\.."
	
	#Write-Log "Uninstall old Lenovo Battery Gauge(which install by MSI). It might not exist"
	#UninstallMsiOldBatteryGauge

	Write-Log "Details of dest package info(new version)-------------------------"
	PrintDestPackageDetails
	
	Remove-PSDrive -Name HKU

	Write-Log "Update-Install sucessful!"
	Exit
}


# ::***********************************************************************************************
# :: [Register PluginsContract.dll,Register LenovoBatteryGaugePackage.dll ]
# ::***********************************************************************************************
Write-Log "Register BatteryGauge related components"
RegisterNewBatteryGauge


# ::***********************************************************************************************
# :: [ Pin to task bar if needed]
# ::***********************************************************************************************
Write-Log "installing param is: $Pinned"
if ($Pinned -eq 1)
{
	$retCtrl = BatteryGaugeIconControlEx($ShowBg)
	if($retCtrl -eq 0)
	{
		Write-Log "Try to show BatteryyGauge again..., ReturnCode=$LastExitCode"
		Start-Sleep -Milliseconds 400	
		$retCtrl = BatteryGaugeIconControlEx($ShowBg)
	}
	Write-Log "Show BatteryGauge on taskbar, show = $retCtrl, ReturnCode=$LastExitCode"
}


Remove-PSDrive -Name HKU

Write-Log "Install sucessful!"
Exit

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA7ZyYednpeENkq
# iHhpg7v248Vdon8xz2a7MN94iDFxlaCCIS8wggWQMIIDeKADAgECAhAFmxtXno4h
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBvwamS347X
# n0UJsopmGN40PJq7om1QBbzIKAqn4Re8OzANBgkqhkiG9w0BAQEFAASCAgBPe9Ca
# OkK4tQH1XZzpmv2EEEyldzDH1uBHKl+pDFB1YnYadShws9nbRVscNjGOkWrxnpqy
# VLK18Vj5wd/IjPOoYIyR/jFSG/l6Ce+pu1cI0qgyhjsAFglqFYo0bCb1soXKKKp8
# a/x/XIOnoVJIkiiSQtuY97H8MUmTiaCFrwEK6ufu6Zl+63DzYnr8uQfSDmGb8XGh
# 4EWQQzFTl4zCeCUvUGWWpe1wXrRdcW3Auv/pUtWH063dItwLFs6B54vrUPqr4b7d
# 8WJh7imYsgnowHz1FuZRJq8izblobzCpBaIDJFR8bpMP99Hc6F2wtFFZrUhFAnKb
# JkAgsb6K7PXOwO5HmRRtohFqsL9EcxNebprBqaXsInxDFPKpDMMdmr5djaGQ0mQs
# p87FY2pUVMI6Z1SgP+W5iJ/Bud+q6SyuLxXj/2Yxf6NXj5nNY7Q6SStgKbo+eRec
# eOHNumpDcMHZ9F5coVazx4Q00YUHO+ieCroy32plDNa62xQ5X/F3FTJDwoBlCIUM
# cZrG34+0IDrD7RF/5UWdsyXv/Fd3oN5ykCiKAvwMVCYMzbX7bmdXhmDcoZYrnpsj
# 5wvy+3XnZ/D8oOf3MF50YOgv/xz57biY03OepHkKlWU50uLp5CT5OajbbphE5FfZ
# M+S1es8X4zLTaTO1gBwxEeHWP0zbuYOObjiTwaGCAyAwggMcBgkqhkiG9w0BCQYx
# ggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1
# NiBUaW1lU3RhbXBpbmcgQ0ECEAp6SoieyZlCkAZjOE2Gl50wDQYJYIZIAWUDBAIB
# BQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0y
# MjA1MTIwODE5NTVaMC8GCSqGSIb3DQEJBDEiBCANXvb7MCTNpyjtoQLHG6ledu1f
# HCEvOVl0w8GwKUmZ6DANBgkqhkiG9w0BAQEFAASCAgANd5KqzS8AVOEkhjJ+UseY
# uanM9zlQhWChwfBIZTV6grq14vuYryAQ5zTt5ZUpxlZGlF/kGTftHWz/9V26A82u
# OiOAQBM+rg5jfOpHz2LPAQ/fJ/b0jaXdRw5ypfLEj+gMJaTduvAm0p+flyDNwK16
# yNJZ6KFLxDkxmgmlips6bsT2xrWI1DdfdsWvZp6rWITY4IKA0bKt6kmrbhI9CUJE
# LdW9vvq96hOyoLFO36V+lsU72bWawLMjXxeqW1Db905yxuHpbd+hNmSZWR5UcEiI
# slJu1oZ7BJQI1jpROBaujXWSdmD+zMA45QsP7ac8U6ZrnI+iHlHFG4IEBRpob5VF
# ib8DFoEn27TMfz4zHfylaSxWlMk8o44gkCi59fpilt4wVnNaCdN299ppbGWwRaR+
# epfmeHle9wOmaUqShOqZRdjC8SdApY52bPphPUz4TEjlGlu3aWrQjRGO53cMfK1k
# I9VssoofAptfsS9AtdgzN+VpDClA26F1fpdNsg5mFQZ4vd4Quwq1kZTmbrZZ/asH
# GJeB2YnU+anB8SdAPD+OKIwkpG6sYTSSSKXyddsU/YLmZpXRYm6uS6LvbSU46f2y
# y3qMwYW0u76re6E9DoFi9gTMue7GuIdxWpqa4jJbY55ddm7jyp1N8vIZuP//KjFO
# 7fOs2YGZss/+vo1shqjBrA==
# SIG # End signature block
