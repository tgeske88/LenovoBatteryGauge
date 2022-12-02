$path = "C:\ProgramData\Lenovo\ImController\Plugins\LenovoBatteryGaugePackage\"
$acl = Get-Acl $path

# administrator rule
$sid = [System.Security.Principal.SecurityIdentifier]"S-1-5-32-544"
$access = [System.Security.AccessControl.FileSystemRights]"FullControl"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$access,3,0,0)
$acl.AddAccessRule($rule)
 
# everyone rule
$sid = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
$access = [System.Security.AccessControl.FileSystemRights]"FullControl"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$access,3,0,0)
$acl.AddAccessRule($rule)

# system rule
$sid = [System.Security.Principal.SecurityIdentifier]"S-1-5-18"
$access = [System.Security.AccessControl.FileSystemRights]"FullControl"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$access,3,0,0)
$acl.AddAccessRule($rule)

# logon user rule
$sidvalue = ([System.Security.Principal.NTAccount]"$env:userdomain\$env:username").Translate([System.Security.Principal.Securityidentifier]).Value
$sid = [System.Security.Principal.SecurityIdentifier]"$sidvalue"
$access = [System.Security.AccessControl.FileSystemRights]"FullControl"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$access,3,0,0)
$acl.AddAccessRule($rule)
 
# set-acl
Set-Acl $path $acl
