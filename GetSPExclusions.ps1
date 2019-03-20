<#
.SYNOPSIS
  Discover Recommended Antivirus Exclusions on a SharePoint Server.
 
.DESCRIPTION
  Builds an array of recommended folder exclusions (http://support.microsoft.com/kb/952167). Use the array to add excusions to Windows Defenderor us for another antivirus products. Requires Local Admin and Farm Admin Rights.

.PARAMETER Defender
  If present will execute the commands to add the discovered exclusions to Windows Defender.

.INPUTS
  None

.OUTPUTS
  Log file stored in Working Directory (Get-Date -Format 'yyyyMMdd')+"-AVExcludedPaths.log

.NOTES
  Version:        1.0
  Author:         Dennis Goss
  Creation Date:  2019-03-20
  Purpose/Change: Initial script development
  
.EXAMPLE
  Run the GetSPExclusions script to discover the recommended paths to be excluded and add the exclusions to Windows Defender (-Defender parameter)
  GetSPExlusions -Defender
#>

Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction 0
Import-Module WebAdministration -ErrorAction 0
$LogPath = $PWD.Path+"\"+(Get-Date -Format 'yyyyMMdd')+"-AVExcludedPaths.log"
$message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - Logging Started"
Write-Output $message | Out-File $LogPath -Append

[System.Collections.ArrayList]$excludePaths = @()
$SPVersion = (Get-PSSnapin Microsoft.SharePoint.PowerShell).Version.Major

Switch ($SPVersion)
{
    16 #SP2016/2019
    {
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - SharePoint 2016 or SharePoint 2019 is installed - getting exclusions"
        Write-Output $message | Out-File $LogPath -Append
        $path = Get-SPEnterpriseSearchComponent -SearchTopology (Get-SPEnterpriseSearchServiceApplication).ActiveTopology | Where-Object {$_.Name -like "Index*"} | Select-Object -expandproperty RootDirectory
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = (Get-SPDiagnosticConfig).LogLocation
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $wssVirtualDirectoryRoots = Get-ChildItem iis:\sites | Select-Object-Object -ExpandProperty physicalPath
        $wssVirtualDirectoryRoots | ForEach-Object {$excludePaths.Add($_) >> $null}
        $iisTempRaw = $wssVirtualDirectoryRoots[0] -split '\\'
        $path = $iisTempRaw[0]+"\"+$iisTempRaw[1]+"\temp\IIS Temporary Compressed Files"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $MAs = Get-SPManagedAccount | Select-Object-Object -ExpandProperty UserName
        foreach($MA in $MAs)
        {
            $ManAcctRaw = $MA.Split("\")
            $ManAcct = $ManAcctRaw[1]
            $path = "C:\Users\"+$ManAcct+"\AppData\Local\Temp"
            $excludePaths += $path
            $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
            Write-Output $message | Out-File $LogPath -Append
        }
        $genSetupPathRaw = ([Microsoft.Sharepoint.Utilities.SpUtility]::GetGenericSetupPath("")).Split("\")
        $genSetupPathLen = $genSetupPathRaw.Length - 3
        $path = [string]::Join("\",$genSetupPathRaw[0..$genSetupPathLen])
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = Get-SPEnterpriseSearchServiceInstance | Select-Object-Object -ExpandProperty DefaultIndexLocation
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = "%SystemDrive%\Users\Default\AppData\Local\Temp"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = "%AllUsersProfile%\Microsoft\SharePoint"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = "%SystemRoot%\System32\LogFiles"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = "%SystemRoot%\SysWow64\LogFiles"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Temporary ASP.NET Files"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        $path = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Config"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
    }
    15 #SP2013
    {
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - SharePoint 2013 - getting exclusions"
        Write-Output $message | Out-File $LogPath -Append
    }
    14 #SP2010
    {
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - SharePoint 2010 is installed - getting exclusions"
        Write-Output $message | Out-File $LogPath -Append
    }
}
$excludePaths
<#
$excludePaths += Get-SPEnterpriseSearchComponent -SearchTopology (Get-SPEnterpriseSearchServiceApplication).ActiveTopology | Where-Object {$_.Name -like "Index*"} | Select-Object -expandproperty RootDirectory
$excludePaths += (Get-SPDiagnosticConfig).LogLocation
$wssVirtualDirectoryRoots = Get-ChildItem iis:\sites | Select-Object-Object -ExpandProperty physicalPath
$wssVirtualDirectoryRoots | ForEach-Object {$excludePaths.Add($_) >> $null}
$iisTempRaw = $wssVirtualDirectoryRoots[0] -split '\\'
$excludePaths += $iisTempRaw[0]+"\"+$iisTempRaw[1]+"\temp\IIS Temporary Compressed Files"
$MAs = Get-SPManagedAccount | Select-Object-Object -ExpandProperty UserName
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
$excludePaths += Get-SPEnterpriseSearchServiceInstance | Select-Object-Object -ExpandProperty DefaultIndexLocation
$excludePaths += "%SystemDrive%\Users\Default\AppData\Local\Temp"
$excludePaths += "%AllUsersProfile%\Microsoft\SharePoint"
$excludePaths += "%SystemRoot%\System32\LogFiles"
$excludePaths += "%SystemRoot%\SysWow64\LogFiles"
$excludePaths += [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Temporary ASP.NET Files"
$excludePaths += [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Config"

$excludePaths

Set-MpPreference -ExclusionPath $excludePaths
Get-MpPreference | Select-Object-Object -ExpandProperty ExclusionPath | Format-List
#>