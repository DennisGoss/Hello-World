<#
Designed to add exclusions to Windows Defender based on KB or build an Array of paths to exclude for another antivirus products
http://support.microsoft.com/kb/952167
#>

Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction 0
Import-Module WebAdministration -ErrorAction 0
$LogPath = $PWD.Path+"\"+(Get-Date -Format 'yyyyMMdd')+"-AVExcludedPaths.Log"
$message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - Logging Started"
Write-Output $message | Out-File $LogPath -Append

[System.Collections.ArrayList]$excludePaths = @()
$SPVersion = (Get-PSSnapin Microsoft.SharePoint.PowerShell).Version.Major

Select Case $SPVersion
    16 #SP2016/2019
    {
        Write-Output
    }
    15 #SP2013
    {

    }
    14 #SP2010
    {

    }


$excludePaths += Get-SPEnterpriseSearchComponent -SearchTopology (Get-SPEnterpriseSearchServiceApplication).ActiveTopology | ? {$_.Name -like "Index*"} | Select -expandproperty RootDirectory
$excludePaths += (Get-SPDiagnosticConfig).LogLocation
$wssVirtualDirectoryRoots = gci iis:\sites | Select -ExpandProperty physicalPath
$wssVirtualDirectoryRoots | %{$excludePaths.Add($_) >> $null}
$iisTempRaw = $wssVirtualDirectoryRoots[0] -split '\\'
$excludePaths += $iisTempRaw[0]+"\"+$iisTempRaw[1]+"\temp\IIS Temporary Compressed Files"
$MAs = Get-SPManagedAccount | Select -ExpandProperty UserName
foreach($MA in $MAs)
{
    $ManAcctRaw = $MA.Split("\")
    $ManAcct = $ManAcctRaw[1]
    $excludePaths += "C:\Users\"+$ManAcct+"\AppData\Local\Temp"
}
$genSetupPathRaw = ([Microsoft.Sharepoint.Utilities.SpUtility]::GetGenericSetupPath("")).Split("\")
$genSetupPathLen = $genSetupPathRaw.Length - 3
$genSetupPath = [string]::Join("\",$genSetupPathRaw[0..$genSetupPathLen])
$excludePaths += $genSetupPath
$excludePaths += Get-SPEnterpriseSearchServiceInstance | Select -ExpandProperty DefaultIndexLocation
$excludePaths += "%SystemDrive%\Users\Default\AppData\Local\Temp"
$excludePaths += "%AllUsersProfile%\Microsoft\SharePoint"
$excludePaths += "%SystemRoot%\System32\LogFiles"
$excludePaths += "%SystemRoot%\SysWow64\LogFiles"
$excludePaths += [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Temporary ASP.NET Files"
$excludePaths += [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Config"

$excludePaths

Set-MpPreference -ExclusionPath $excludePaths
Get-MpPreference | Select -ExpandProperty ExclusionPath | fl