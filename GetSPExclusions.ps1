<#
.SYNOPSIS
  Discover Recommended Antivirus Exclusions on a SharePoint Server.
 
.DESCRIPTION
  Builds an array of recommended folder exclusions (http://support.microsoft.com/kb/952167). Use the array to add excusions to Windows 
  Defenderor us for another antivirus products. Requires Local Admin and Farm Admin Rights.

.PARAMETER Defender
  If present will execute the commands to add the discovered exclusions to Windows Defender. Disabled by default.

.INPUTS
  None

.OUTPUTS
  Log file stored in Working Directory (Get-Date -Format 'yyyyMMdd')+"-GetSPExclusions.log

.NOTES
  Version:        1.0
  Author:         Dennis Goss
  Creation Date:  2019-03-20
  Purpose/Change: Initial script development
  
.EXAMPLE
  Run the GetSPExclusions script to discover the recommended paths to be excluded and add the exclusions to Windows Defender
  GetSPExlusions -Defender
#>
Param 
(
    [switch]$defender = $false
)
#Add SharePoint Snapin and WebAdministration Module
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction 0
Import-Module WebAdministration -ErrorAction 0

#Define Logpath
$LogPath = $PWD.Path+"\"+(Get-Date -Format 'yyyyMMdd')+"-AVExcludedPaths.log"
$message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - Logging Started"
Write-Output $message | Out-File $LogPath -Append

#Define Array to contain discovered exclusion paths
[System.Collections.ArrayList]$excludePaths = @()

#Discover SharePoint version for later use (some paths vary based on the version)
$SPVersion = (Get-PSSnapin Microsoft.SharePoint.PowerShell).Version.Major

#Use the SharePoint Major Version to discover the correct exclusions
Switch ($SPVersion)
{
    16 #SP2016/2019
    {
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - SharePoint 2016 or SharePoint 2019 is installed - getting exclusions"
        Write-Output $message | Out-File $LogPath -Append
        #Find the Search Index Component Root Folder - should work for 2013/2016/2019 but probably not 2010
        $path = Get-SPEnterpriseSearchComponent -SearchTopology (Get-SPEnterpriseSearchServiceApplication).ActiveTopology | Where-Object {$_.Name -like "Index*"} | Select-Object -expandproperty RootDirectory
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Find the ULS Log Location - should work for all versions
        $path = (Get-SPDiagnosticConfig).LogLocation
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Find the IIS Virtual Directories currently in use (best to run this after your Farm is built or re-run as needed) - should work on all versions
        $wssVirtualDirectoryRoots = Get-ChildItem iis:\sites | Select-Object -ExpandProperty physicalPath
        $wssVirtualDirectoryRoots | ForEach-Object {$excludePaths.Add($_) >> $null}
        $wssVirtualDirectoryRoots | ForEach-Object {$message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $_ - path discovered"; Write-Output $message | Out-File $LogPath -Append}
        #Find the IIS Temporary Compressed Files Folder - should work on all versions
        $iisTempRaw = $wssVirtualDirectoryRoots[0] -split '\\'
        $path = $iisTempRaw[0]+"\"+$iisTempRaw[1]+"\temp\IIS Temporary Compressed Files"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Find all managed accounts in order to exclude their user profile folders - should work on all versions
        $MAs = Get-SPManagedAccount | Select-Object -ExpandProperty UserName
        foreach($MA in $MAs)
        {
            $ManAcctRaw = $MA.Split("\")
            $ManAcct = $ManAcctRaw[1]
            $path = "C:\Users\"+$ManAcct+"\AppData\Local\Temp"
            $excludePaths += $path
            $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
            Write-Output $message | Out-File $LogPath -Append
        }
        #Find the SharePoint Installtion Root Folder - might work for all versions
        $genSetupPathRaw = ([Microsoft.Sharepoint.Utilities.SpUtility]::GetGenericSetupPath("")).Split("\")
        $genSetupPathLen = $genSetupPathRaw.Length - 3
        $path = [string]::Join("\",$genSetupPathRaw[0..$genSetupPathLen])
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Find the Search Service App Index Location (assumes one Search Service App) - might work for 2013 probably 2010
        $path = Get-SPEnterpriseSearchServiceInstance | Select-Object -ExpandProperty DefaultIndexLocation
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Define the Default User Profile Temp folder - should work on all versions
        $path = "%SystemDrive%\Users\Default\AppData\Local\Temp"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Define the All Users Profile SharePoint folder (stores config cache and other cache) - should work on all versions
        $path = "%AllUsersProfile%\Microsoft\SharePoint"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Define the default log file folder - should work on all versions
        $path = "%SystemRoot%\System32\LogFiles"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Define the default 64 bit log file folder - should work on all versions
        $path = "%SystemRoot%\SysWow64\LogFiles"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Find the default folder used for Temporary ASP.NET files - should work on all versions
        $path = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Temporary ASP.NET Files"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
        #Find the default folder used for ASP.NET Config files - should work on all versions
        $path = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"Config"
        $excludePaths += $path
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - $path - path discovered"
        Write-Output $message | Out-File $LogPath -Append
    }
    15 #SP2013
    {
      <#TO DO: Build/Test SP2013 Farm#>
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - SharePoint 2013 - getting exclusions"
        Write-Output $message | Out-File $LogPath -Append
    }
    14 #SP2010
    {
      <#TO DO: Build/Test SP2010 Farm#>
        $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - SharePoint 2010 is installed - getting exclusions"
        Write-Output $message | Out-File $LogPath -Append
    }
}

if($defender)
{ 
  $message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - Defender Parameter is present - adding exclusions to Windows Defender"
  Write-Output $message | Out-File $LogPath -Append
  Set-MpPreference -ExclusionPath $excludePaths -Verbose
}

#uncomment next line for console output of the excludedPaths array
#$excludePaths

$message = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+" - Logging Stopped"
Write-Output $message | Out-File $LogPath -Append