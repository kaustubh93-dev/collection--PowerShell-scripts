#===================================================================

# This sample is provided as is and is not meant for use on a 
# production environment. It is provided only for illustrative 
# purposes. The end user must test and modify the sample to suit 
# their target environment.
# 

# Microsoft can make no representation concerning the content of 
# this sample. Microsoft is providing this information only as a 
# convenience to you. This is to inform you that Microsoft has not 
# tested the sample and therefore cannot make any representations 
# regarding the quality, safety, or suitability of any code or 
# information found here.
# 

#===================================================================

 

 

<#
    .SYNOPSIS 
       Checks the hardware state of disks attached to $ClusterName Nodes

    .DESCRIPTION 
       The script checks storage against known issues

    .NOTES  
    Author     : Richard Hawes
    Version    : 5.7

#>

 

 

$ClusterName = "S-Cluster"
$Version = "5.7"

$answer = Read-Host "Do you require verbose logging? (Y)es, to run without logging press Enter"

 

switch ($answer) {

    Y {

        $LoggingLevel = "V"

        Write-Host "Verbose logging selected"

    }

    $null {

        $LoggingLevel = "Default"

        Write-Host "Default value selected"

    }

            

    "" {

        $LoggingLevel = "Default"

        Write-Host "Default value selected"

    }

    default { 'Default value selected' }

}

   

 

#Requires -Modules PNPDevice, FailoverClusters

Import-Module PNPDevice

Import-Module FailoverClusters

 

 

# Define common functions that are used in the script

function Write-Color([String[]]$Text, [ConsoleColor[]]$ForeGroundColor, [ConsoleColor[]]$BackGroundColor) {

    for ($i = 0; $i -lt $Text.Length; $i++) {

        $Color = @{}

        If ($ForeGroundColor -and $BackGroundColor) {

            $Color = @{

                ForegroundColor = $ForeGroundColor[$i % ($ForeGroundColor.count)]

                BackgroundColor = $BackGroundColor[$i % ($BackGroundColor.count)]

            }

        }

        ElseIf ($ForeGroundColor) {

            $Color = @{

                ForegroundColor = $ForeGroundColor[$i % ($ForeGroundColor.count)]

            }

        }

        ElseIf ($BackGroundColor) {

            $Color = @{

                BackgroundColor = $BackGroundColor[$i % ($BackGroundColor.count)]

            }

        }

        Write-Host $Text[$i] @color -NoNewLine

    }

    Write-Host

}

 

 

function Get-DiskInfoGraphicDisplay { 

 

    $thresold = 40 

    Write-Host "`n" 

    Write-Host " " -BackgroundColor Green -NoNewline 

    Write-Host "Used Space < 80%" -NoNewline "  "  

    Write-Host " " -BackgroundColor Yellow -NoNewline 

    Write-Host "Used Space > 80%" -NoNewline "  "  

    Write-Host " " -BackgroundColor Red -NoNewline 

    Write-Host "Used Space > 90%" -NoNewline "  " 

    Write-Host `n

 

 

    # Get Cluster Shared Volumes

    ForEach ($v in Get-ClusterSharedVolume -cluster $ClusterName) {      

        If ($v.State -match 'Online') {

            $usedSize = ($v.SharedVolumeInfo.Partition.size - $v.SharedVolumeInfo.Partition.FreeSpace) / $v.SharedVolumeInfo.Partition.Size 

            $freeDisk = $v.SharedVolumeInfo.Partition.FreeSpace / $v.SharedVolumeInfo.Partition.Size 

            $percentDisk = "{0:P2}" -f $freeDisk 

            Write-Host ([regex]::match($v.name, '\((.*?)\)').Groups[1].Value).PadRight(20) -ForegroundColor White -NoNewline 

            Switch ($PercentDisk) {

                { $_ -lt 10 } { Write-Host (" " * ($usedSize * $thresold)) -BackgroundColor Red -NoNewline }

                { ($_ -gt 10) -and ($_ -lt 20) } { Write-Host (" " * ($usedSize * $thresold)) -BackgroundColor Yellow -NoNewline }

                { $_ -gt 20 } { Write-Host (" " * ($usedSize * $thresold)) -BackgroundColor Green -NoNewline }

            }

            Write-Host (" " * ($freeDisk * $thresold))  -BackgroundColor White -NoNewline  

            Write-Host " " $percentDisk "Free" "" 

        }

        Else {

            Write-Host "`n" 

            Write-Host "Cluster Shared Volume is not in an expected online state"

            $v

        }

    }

}

 

 

function Write-Log {

    [CmdletBinding()]

    param(

        [Parameter()]

        $Message,

 

        [Parameter()]

        [ValidateNotNullOrEmpty()]

        [ValidateSet('INFO', 'WARNING', 'ERROR', 'OUTPUT')]

        [string]$Severity = 'INFO'

    )

 

    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

 

    if (!$Message -and $LoggingLevel -match "V" ) {

        [String]$Message = "No Data Found"

        "$FormattedDate $Severity $Message $Servername" | Out-File -FilePath $DataColLog -Append -Encoding ascii -NoClobber

    }

    Elseif ($Severity -eq "OUTPUT" -and $LoggingLevel -match "V") {

        "$FormattedDate $Severity :" | Out-File -FilePath $DataColLog -Append -Encoding ascii -NoClobber

        $Message | Out-File -FilePath $DataColLog -Append -Encoding ascii -NoClobber   

    }

    Elseif ($LoggingLevel -match "V") {

        $Message = [String]$Message 

        "$FormattedDate $Severity $Message $Servername" | Out-File -FilePath $DataColLog -Append -Encoding ascii -NoClobber

    }

    

        

    if ($Severity -eq "ERROR" -and $LoggingLevel -match "V" ) {

        Write-Host "$FormattedDate $Severity $Message $Servername" -ForegroundColor Red

    }

    if ($Severity -eq "WARNING" -and $LoggingLevel -match "V") {

        Write-Host "$FormattedDate $Severity $Message $Servername" -ForegroundColor Yellow

    }

    if ($Severity -eq "INFO" -and $LoggingLevel -match "V") {

        Write-Host "$FormattedDate $Severity $Message $Servername"  -ForegroundColor Cyan

    }

}

 

# Setup log paths for verbose logging

function Get-LogPaths {

    # Define default locations for script

    $Script:DataColLog = "C:\StorageDiagCollectionResults.log"

    $Script:DataCollectionDir = "C:\Temp\CSS_StorageDiag" 

 

    if (Test-Path -Path $DataColLog -PathType Any) {

        Remove-Item -Path $DataColLog -Confirm:$false -Recurse | Out-Null

    }

    New-Item $DataColLog | Out-Null

 

    if (Test-Path -Path $DataCollectionDir -PathType Any) {

        Remove-Item -Path $DataCollectionDir -Confirm:$false -Recurse | Out-Null

    }

    New-Item  -ItemType directory -Path $DataCollectionDir | Out-Null

 

}

 

 

# Collect the results from Cluster nodes and compress

function Get-Results {

 

    if ($LoggingLevel -match "V") {

        Write-Log -Message "CollectResults : Gathering results from infrastructure nodes"

        

        if ($null -ne $Nodes) {

            # Create remote compression jobs on data nodes

            $RemoteCompressionJob = Invoke-Command -ComputerName $($Nodes | Where-Object { $_ -ne $env:COMPUTERNAME }) -ScriptBlock {

                if (Test-Path -Path $Using:DataCollectionDir) {

                    Import-Module -Name "Microsoft.PowerShell.Archive" -Verbose -Force 

                    Compress-Archive -Path $Using:DataCollectionDir\* -DestinationPath "$Using:DataCollectionDir\$env:COMPUTERNAME.zip"

                }

            } -AsJob -JobName CompressResults -InformationAction SilentlyContinue 

 

            # Wait for remote compression jobs to complete

            $ExecutionTime = 0

            do {

                Start-Sleep -Seconds 15

                $ExecutionTime += 15

                Write-Log -Message "CollectResults : $(($RemoteCompressionJob.ChildJobs.State -eq 'Completed').Count) out of $($RemoteCompressionJob.ChildJobs.Count) remote compression jobs completed. $ExecutionTime seconds elapsed" 

            }until($RemoteCompressionJob.State -ne "Running" -or $ExecutionTime -ge 900)

            if ($RemoteCompressionJob.State -ne "Completed") {

                if ($ExecutionTime -ge 900) {

                    Write-Log -Message "CollectResults : Operation has timed out for parent job." WARNING

                    Get-Job -Id $RemoteCompressionJob.Id | Stop-Job -Confirm:$false

                }

 

                $FailedChildJobs = $RemoteCompressionJob.ChildJobs | Where-Object { $_.State -ne "Completed" }

                foreach ($FailedChildJob in $FailedChildJobs) {

                    Write-Log -Message "CollectResults : Remote compression job for $($FailedChildJob.Location) has failed with State: $($FailedChildJob.State) | Status: $($FailedChildJob.StatusMessage)" WARNING

                }

            }

            elseif ($RemoteCompressionJob.State -eq "Completed") {

                Write-Log -Message "CollectResults : $(($RemoteCompressionJob.ChildJobs.State -eq 'Completed').Count) out of $($RemoteCompressionJob.ChildJobs.Count) remote compression jobs completed"

            }

 

            # Transfer compressed directory from data nodes that completed

            foreach ($ChildJob in $RemoteCompressionJob.ChildJobs) {

                if ($ChildJob.State -eq "Completed") {

                    if (Test-Path -Path "[file://$($ChildJob.Location)/c$/Temp/CSS_StorageDiag]\\$($ChildJob.Location)\c$\Temp\CSS_StorageDiag" -PathType Container) {

                        # Transfer compressed directory from data node

                        Write-Log -Message "CollectResults : Retrieving the results from $($ChildJob.Location)"

                        Move-Item -Path "[file://$($ChildJob.Location)/c$/Temp/CSS_StorageDiag/*.zip]\\$($ChildJob.Location)\c$\Temp\CSS_StorageDiag\*.zip" -Destination $DataCollectionDir

 

                        # Remove the files from the remote node

                        Write-Log -Message "CollectResults : Removing the results from $($ChildJob.Location)"

                        Remove-Item -Path "[file://$($ChildJob.Location)/c$/Temp/CSS_StorageDiag]\\$($ChildJob.Location)\c$\Temp\CSS_StorageDiag" -Recurse -Force

                    }

                    else {

                        Write-Log -Message "CollectResults : Unable to locate any files under [file://$($ChildJob.Location)/c$/Temp/CSS_StorageDiag]\\$($ChildJob.Location)\c$\Temp\CSS_StorageDiag" WARNING

                    }

                }

                elseif ($ChildJob.State -ne "Completed") {

                    Write-Log -Message "CollectResults : Skipping data collection for $($ChildJob.Location) as remote compression job failed. Please gather the results

                manually from [file://$($ChildJob.Location)/c$/Temp/CSS_StorageDiag]\\$($ChildJob.Location)\c$\Temp\CSS_StorageDiag" WARNING

                }

            }

        }

        else {

            Write-Log -Message "CollectResults : No data nodes defined"

        }

 

        # Transfer the files to remote network share if exists

        Move-Item -Path $DataColLog -Destination $DataCollectionDir -Verbose

 

 

        if (Test-Path -Path X:) {

            Try {

                Copy-Item -Path $DataCollectionDir\* -Destination "X:\$RemoteShareFolder" -Recurse -Verbose

            }

            Catch {

                Write-Host "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) WARNING CollectResults : Unable to copy results to $RemoteShareFolder" -ForegroundColor Yellow

            }

 

            # Cleanup the mapped network drive and any left over objects

            Write-Host "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) INFO CollectResults : Removing mapped network drive to $RemoteSharePath" -ForegroundColor Cyan

            Remove-PSDrive -Name X -Verbose

            Remove-Item -Path $DataCollectionDir -Recurse -Confirm:$false | Out-Null

        }

        else {

            # Compress all the data into a single zip folder

            Import-Module -Name "Microsoft.PowerShell.Archive" -Verbose -Force 

            Compress-Archive -Path $DataCollectionDir\* -DestinationPath "$DataCollectionDir\Storage_DataCollection_$((Get-Date).ToString('yyyyMMdd-hhmmss')).zip"

            Get-ChildItem -Path $DataCollectionDir -Recurse | Where-Object { $_.Name -notlike "Storage_DataCollection_*.zip" } | Remove-Item -Recurse

 

            Write-Host "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) INFO CollectResults : Files have been saved to $DataCollectionDir. Transfer the files using the following command after updating the Destination and FromSession variables:

            Copy-Item -Path $DataCollectionDir -Destination C:\Example -FromSession <SessionName> -Recurse -Verbose

        

        Once the zip file has been moved, please cleanup the directory using the following command:

            Remove-Item -Path $DataCollectionDir -Recurse

 

        " -ForegroundColor Green

        }

    }

}

 

 

# Get the disk partitions

function Get-PartitionType(

    $id, $name = $null

) {

    switch -Regex ($id) {

        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" { "System" }

        "e3c9e316-0b5c-4db8-817d-f92df00215ae" { "Reserved" }

        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" { "Basic" }

        "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" { "LDM Metadata" }

        "af9b60a0-1431-4f62-bc68-3311714a69ad" { "LDM Data" }

        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" { "Recovery" }

        "e75caf8f-f680-4cee-afa3-b001e56efc2d" { "Space Protective" }

        "PARTITION_SPACES_GUID" { "Space Protective" }

        "eeff8352-dd2a-44db-ae83-bee1cf7481dc" { "Microsoft SBL Cache Store" }

        "03aaa829-ebfc-4e7e-aac9-c4d76c63b24b" { "Microsoft SBL Cache Hdd" }

        "db97dba9-0840-4bae-97f0-ffb9a327c7e1" { "[Clus|$name]" }

        "PARTITION_CLUSTER_GUID" { "[Clus|$name]" }

        Default { "[$id|$name]" }

    }

}

 

 

function Read-DataMapper {

    

    param ($Result)

 

    $Result.diskhealth | get-member -type NoteProperty | foreach-object {

 

        switch -Wildcard ($_.name) {

 

            'SBLAttribute' {

                $i = -1

                Switch -Wildcard ($Result.DiskHealth.$_) {

                    '0' { $i++; $Result.DiskHealth[$i].SBLAttribute = 'Default' }

                    '1' { $i++; $Result.DiskHealth[$i].SBLAttribute = 'Enabled' }

                    '2' { $i++; $Result.DiskHealth[$i].SBLAttribute = 'Disabled' }

                    '4' { $i++; $Result.DiskHealth[$i].SBLAttribute = 'Maintenance' }

                    '8' { $i++; $Result.DiskHealth[$i].SBLAttribute = 'No_Virtual_Enclosure' }

                    '16' { $i++; $Result.DiskHealth[$i].SBLAttribute = 'Block_RW' }

                    Default { $i++ }

                } # End of Switch SBLAttribute

            }

 

            'SBLDiskCacheState' {

                $i = -1

                Switch -Wildcard ($Result.DiskHealth.$_) {

                    '0' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'Default' } 

                    '0' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateUnknown' }

                    '1' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateConfiguring' }

                    '2' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateInitialized' }

                    '3' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateInitializedAndBound' }

                    '4' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateDraining' }

                    '5' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateDisabling' }

                    '6' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateDisabled' }

                    '7' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateMissing' }

                    '8' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateOrphanedWaiting' }

                    '9' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateOrphanedRecovering' }

                    '10' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateFailedMediaError' }

                    '11' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateFailedProvisioning' }

                    '12' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateReset' }

                    '13' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateRepairing' }

                    '2000' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIneligibleDataPartition' }

                    '2001' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIneligibleNotGPT' }

                    '2002' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIneligibleNotEnoughSpace' }

                    '2003' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIneligibleUnsupportedSystem' }

                    '2004' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIneligibleExcludedFromS2D' }

                    '2999' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIneligibleForS2D' }

                    '3000' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateSkippedBindingNoFlash' }

                    '3001' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateIgnored' }

                    '3002' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateNonHybrid' }

                    '9000' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateInternalErrorConfiguring' }

                    '9001' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateMarkedBad' }

                    '9002' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateMarkedMissing' }

                    '9003' { $i++; $Result.DiskHealth[$i].SBLDiskCacheState = 'CacheDiskStateInStorageMaintenance' }   

                    Default { $i++ }                    

                } # End of Switch SBLDiskCacheState

            }

 

            'SBLCacheUsageCurrent' {

                $i = -1

                Switch -Wildcard ($Result.DiskHealth.$_) {

                    '0' { $i++; $Result.DiskHealth[$i].SBLCacheUsageCurrent = 'NonHybrid' }

                    '1' { $i++; $Result.DiskHealth[$i].SBLCacheUsageCurrent = 'Data' }

                    '2' { $i++; $Result.DiskHealth[$i].SBLCacheUsageCurrent = 'Cache' }

                    '3' { $i++; $Result.DiskHealth[$i].SBLCacheUsageCurrent = 'Auto' }

                    Default { $i++ }

                } # End of Switch SBLCacheUsageCurrent

            }

 

            'SBLCacheUsageDesired' {

                $i = -1

                Switch -Wildcard ($Result.DiskHealth.$_) {

                    '0' { $i++; $Result.DiskHealth[$i].SBLCacheUsageDesired = 'NonHybrid' }

                    '1' { $i++; $Result.DiskHealth[$i].SBLCacheUsageDesired = 'Data' }

                    '2' { $i++; $Result.DiskHealth[$i].SBLCacheUsageDesired = 'Cache' }

                    '3' { $i++; $Result.DiskHealth[$i].SBLCacheUsageDesired = 'Auto' }

                    Default { $i++ }

                } # End of Switch SBLCacheUsageDesired 

            }

        }

    }

    $Result.DiskHealth | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceID 

}

 

 

#Run Logging Function

Write-Log

      

Write-Log -Message "[Setup log paths for jump box]" INFO

Get-LogPaths 

    

        

Write-Log -Message "[Defining functions in variable to allow calling for usage remotely]" INFO

$WriteLogDef = "function Write-Log { ${function:Write-Log} }"

$GetPartitionTypeDef = "function Get-PartitionType { ${function:Get-PartitionType} }"

$GetLogPaths = "function Get-LogPaths { ${function:Get-LogPaths} }"

 

 

Write-Log -Message "[Setup hash tables\Arrays for storage check]" INFO

$StorageCheck = @{}

$StorageCheck["Validation"] = @{}

$Result = @()

 

 

#===================================================================

# Data Gathering:

#===================================================================

 

 

Write-Log -Message "[Get Cluster Shared Volume Usage]" INFO

Write-Host "Cluster Shared Volume Usage:" -ForeGroundColor Yellow 

Write-Log -Message "[Cluster Shared Volume Usage Output]" INFO

Get-DiskInfoGraphicDisplay

Write-Host `n

Write-Host `n

 

 

Write-Log -Message "[Getting Cluster Owner Node]" INFO

$ClusterOwnerNode = (get-clustergroup -name 'cluster group' -Cluster $clustername).OwnerNode.Name 

 

 

Write-Log -Message "[Getting Cluster Node names for $ClusterName]" INFO

$Nodes = (get-clusternode -Cluster $clustername).Name

 

 

Write-Log -Message "[Invoking to Nodes]" INFO

$Result += invoke-command $Nodes {

    

    Param($WriteLogDef, $GetPartitionTypeDef, $GetLogPaths, $LoggingLevel, $ClusterOwnerNode)

 

    #Loading Functions into Node

    . ([ScriptBlock]::Create($WriteLogDef))

    . ([ScriptBlock]::Create($GetPartitionTypeDef))

    . ([ScriptBlock]::Create($GetLogPaths))

 

 

    # Output node hostname       

    $ServerName = Hostname

 

 

 

    Get-LogPaths

    Write-Log -Message "[Setting up log paths]" INFO

 

    Write-Log -Message "[Create Hashtables and arrays on Node]" INFO

    $Healthrunning = @()

    $DiskCheck = @{}

    $allRecords = @{}

    $allRecords["Storage Health"] = @{}

    $allRecords['DiskHealth'] = @()

    $DiskData = @() 

    $PNPLostDisks = @()

    $OSDiskPNPs = @()

 

 

    Write-Log -Message "[Importing Modules]" INFO    

    Import-Module Microsoft.PowerShell.Management

 

 

    Write-Log -Message "[Creating $DataCollectionDir to save results under]" INFO

    New-Item -Path $DataCollectionDir -ItemType Directory -Force | Out-Null

    

 

    Write-Log -Message "[Checking Cluster Health Resource is running]" INFO

    $HealthProcess = Get-Process -ProcessName 'healthpih' -ErrorAction SilentlyContinue | Select-Object Responding, ProcessName

    $Healthrunning = "" |  Select-Object Responding, ProcessName, ServerName

    $Healthrunning.Responding = $HealthProcess.Responding

    $Healthrunning.ProcessName = $HealthProcess.ProcessName

    $Healthrunning.ServerName = $ServerName

    Write-Log -Message $Healthrunning OUTPUT

    

 

    Write-Log -Message "[Create Arrays for Add-Type]" INFO      

    $Assem = ('System.dll', 'System.Data.dll')

 

    Write-Log -Message "[Create C# code for Add-Type]" INFO      

    $Source = @"

          using System;

          using System.Collections;

          using System.Collections.Generic;

          using System.Data;

          using System.Diagnostics;

          using Microsoft.Win32.SafeHandles;

          using System.ComponentModel;

          using System.Runtime.InteropServices;

          using System.Security;

          

          namespace PartitionFinder

          { 

             public class IOCtl

             {

                  private const int GENERIC_READ = unchecked((int)0x80000000);

                  private const int FILE_SHARE_READ = 1;

                  private const int FILE_SHARE_WRITE = 2;

                  private const int OPEN_EXISTING = 3;

                  private const int IOCTL_DISK_GET_DRIVE_LAYOUT_EX = unchecked((int)0x00070050);

                  private const int ERROR_INSUFFICIENT_BUFFER = 122;

             

                  private enum PARTITION_STYLE : int

                  {

                      MBR = 0,

                      GPT = 1,

                      RAW = 2

                  }

              

                  private enum Partition : byte

          

                  {

                      Fat12 = 0x01,

                      XenixRoot = 0x02,

                      Xenixusr = 0x03,

                      Fat16Small = 0x04,

                      Extended = 0x05,

                      Fat16 = 0x06,

                      Ntfs = 0x07,

                      Fat32 = 0x0B,

                      Fat32Lba = 0x0C,

                      Fat16Lba = 0x0E,

                      ExtendedLba = 0x0F,

                      HiddenFAT12 = 0x11,

                      WindowsDynamicVolume = 0x42,

                      LinuxSwap = 0x82,

                      LinuxNative = 0x83,

                      LinuxLvm = 0x8E,

                      GptProtective = 0xEE,

                      EfiSystem = 0xEF,

                      GptStorageProtective = 0xE7

                 }

          

          

                  [SuppressUnmanagedCodeSecurity()]

                  private class NativeMethods

                  {

                     [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]

                     public static extern SafeFileHandle CreateFile(

                     string fileName,

                     int desiredAccess,

                     int shareMode,

                     IntPtr securityAttributes,

                     int creationDisposition,

                     int flagsAndAttributes,

                     IntPtr hTemplateFile);

          

          

                     [DllImport("kernel32", SetLastError = true)]

                     [return: MarshalAs(UnmanagedType.Bool)]

                    public static extern bool DeviceIoControl(

                     SafeFileHandle hVol,

                     int controlCode,

                     IntPtr inBuffer,

                     int inBufferSize,

                     IntPtr outBuffer,

                     int outBufferSize,

                     ref int bytesReturned,

                     IntPtr overlapped);

                  }

          

          

                  // Needs to be explicit to do the union.

                  [StructLayout(LayoutKind.Explicit)]

                  private struct DRIVE_LAYOUT_INFORMATION_EX

                  {

                      [FieldOffset(0)]

                      public PARTITION_STYLE PartitionStyle;

                      [FieldOffset(4)]

                      public int PartitionCount;

                      [FieldOffset(8)]

                      public DRIVE_LAYOUT_INFORMATION_MBR Mbr;

                      [FieldOffset(8)]

                      public DRIVE_LAYOUT_INFORMATION_GPT Gpt;

                  }

          

          

                  private struct DRIVE_LAYOUT_INFORMATION_MBR

                  {

          

                  }

          

             

                  [StructLayout(LayoutKind.Sequential)]

                  private struct DRIVE_LAYOUT_INFORMATION_GPT

                  {

                      public Guid DiskId;

                      public long StartingUsableOffset;

                      public long UsableLength;

                      public int MaxPartitionCount;

                  }

          

          

                  [StructLayout(LayoutKind.Sequential)]

                  private struct PARTITION_INFORMATION_MBR

                  {

                      public byte PartitionType;

                      [MarshalAs(UnmanagedType.U1)]

                      public bool BootIndicator;

                      [MarshalAs(UnmanagedType.U1)]

                      public bool RecognizedPartition;

                      public UInt32 HiddenSectors;

          

          

                      // helper method - is the hi bit valid - if so IsNTFT has meaning.

                      public bool IsValidNTFT()

                      {

                          return (PartitionType & 0xc0) == 0xc0;

                      }

          

                      // is this NTFT - i.e. an NTFT raid or mirror.

                      public bool IsNTFT()

                      {

                          return (PartitionType & 0x80) == 0x80;

                      }

          

          

                      // the actual partition type.

                      public Partition GetPartition()

                      {

                          const byte mask = 0x3f;

                          return (Partition)(PartitionType & mask);

                      }

                  }

          

          

                  [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]

                  private struct PARTITION_INFORMATION_GPT

                  {

                      [FieldOffset(0)]

                      public Guid PartitionType;

                      [FieldOffset(16)]

                      public Guid PartitionId;

                      [FieldOffset(32)]

                      //DWord64

                      public ulong Attributes;

                      [FieldOffset(40)]

                      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 36)]

                      public string Name;

                  }

          

          

                  [StructLayout(LayoutKind.Explicit)]

                  private struct PARTITION_INFORMATION_EX

                  {

                      [FieldOffset(0)]

                      public PARTITION_STYLE PartitionStyle;

                      [FieldOffset(8)]

                      public long StartingOffset;

                      [FieldOffset(16)]

                      public long PartitionLength;

                      [FieldOffset(24)]

                      public int PartitionNumber;

                      [FieldOffset(28)]

                      [MarshalAs(UnmanagedType.U1)]

                      public bool RewritePartition;

                      [FieldOffset(32)]

                      public PARTITION_INFORMATION_MBR Mbr;

                      [FieldOffset(32)]

                      public PARTITION_INFORMATION_GPT Gpt;

                  }

          

                 public static void SendIoCtlDiskGetDriveLayoutEx(int PhysicalDrive)

                  {

                      DRIVE_LAYOUT_INFORMATION_EX lie = default(DRIVE_LAYOUT_INFORMATION_EX);

                      PARTITION_INFORMATION_EX[] pies = null;

                      using (SafeFileHandle hDevice =

                      NativeMethods.CreateFile("[file://.//PHYSICALDRIVE]\\\\.\\PHYSICALDRIVE" + PhysicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))

                      {

                          if (hDevice.IsInvalid)

                              throw new Win32Exception();

                          // Must run as administrator, otherwise we get "ACCESS DENIED"

                          // We don't know how many partitions there are, so we have to use a blob of memory...

          

                          int numPartitions = 1;

                          bool done = false;

                          do

                          {

                              // 48 = the number of bytes in DRIVE_LAYOUT_INFORMATION_EX up to

                              // the first PARTITION_INFORMATION_EX in the array.

                              // And each PARTITION_INFORMATION_EX is 144 bytes.

                              int outBufferSize = 48 + (numPartitions * 144);

                              IntPtr blob = default(IntPtr);

                              int bytesReturned = 0;

                              bool result = false;

          

          

                              try

                              {

                                  blob = Marshal.AllocHGlobal(outBufferSize);

                                  result = NativeMethods.DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IntPtr.Zero, 0, blob, outBufferSize, ref bytesReturned, IntPtr.Zero);

          

                                  // We expect that we might not have enough room in the output buffer.

                                  if (result == false)

                                  {

                                      // If the buffer wasn't too small, then something else went wrong.

                                      if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)

                                          throw new Win32Exception();

                                      // We need more space on the next loop.

                                      numPartitions += 1;

                                  }

                                  else

                                  {

                                      // We got the size right, so stop looping.

                                      done = true;

          

                                      // Do something with the data here - we'll free the memory before we leave the loop.

                                      // First we grab the DRIVE_LAYOUT_INFORMATION_EX, it's at the start of the blob of memory:

                                      lie = (DRIVE_LAYOUT_INFORMATION_EX)Marshal.PtrToStructure(blob, typeof(DRIVE_LAYOUT_INFORMATION_EX));

                                      // Then loop and add the PARTITION_INFORMATION_EX structures to an array.

                                      pies = new PARTITION_INFORMATION_EX[lie.PartitionCount];

          

                                      for (int i = 0; i <= lie.PartitionCount - 1; i++)

                                      {

                                          // Where is this structure in the blob of memory?

                                          IntPtr offset = new IntPtr(blob.ToInt64() + 48 + (i * 144));

                                          pies[i] = (PARTITION_INFORMATION_EX)Marshal.PtrToStructure(offset, typeof(PARTITION_INFORMATION_EX));

                                      }

                                  }

                              }

                              finally

                              {

                                  Marshal.FreeHGlobal(blob);

                              }

                          } while (!(done));

                      }

                      DumpInfo(lie, pies);

                  }

          

          

                  private static bool IsPart0Aligned(PARTITION_INFORMATION_EX[] pies)

                  {

                      try

                      {

                          if (pies[0].StartingOffset % 4096 == 0)

                          {

                              return true;

                          }

                          else

                          {

                              return false;

                          }

                      }

                      catch

                      {

                          return false;

                      }

                  }

          

          

                  private static void DumpInfo(DRIVE_LAYOUT_INFORMATION_EX lie, PARTITION_INFORMATION_EX[] pies)

                  {

                     if (IsPart0Aligned(pies) == true)

                      {

                          Console.Write("True");

                      }

                      else

                      {

                          Console.Write("false");

                      }

          

          

                      Console.WriteLine("Partition Style: {0}", lie.PartitionStyle);

                      Console.WriteLine("Partition Count: {0}", lie.PartitionCount);

                      switch (lie.PartitionStyle)

                      {

                          case PARTITION_STYLE.MBR:

                              break;

          

                          case PARTITION_STYLE.GPT:

                              Console.WriteLine("Gpt DiskId: {0}", lie.Gpt.DiskId);

                              break;

          

                          default:

                              Console.WriteLine("RAW!");

                              break;

                      }

          

          

                      for (int i = 0; i <= lie.PartitionCount - 1; i++)

          

                      {

                          Console.WriteLine();

                          Console.WriteLine();

                          var _with1 = pies[i];

                          Console.WriteLine("Partition style: {0}", _with1.PartitionStyle);

                          Console.WriteLine("Partition number: {0}", _with1.PartitionNumber);

                          switch (_with1.PartitionStyle)

                          {

                              case PARTITION_STYLE.MBR:

                                  var _with2 = _with1.Mbr;

                                  Console.WriteLine("\r\t  PartitionType - raw value  {0}\n", _with2.PartitionType);

                                  Console.WriteLine("\r\t  BootIndicator              {0}\n", _with2.BootIndicator);

                                  Console.WriteLine("\r\t  RecognizedPartition        {0}\n", _with2.RecognizedPartition);

                                  Console.WriteLine("\r\t  HiddenSectors              {0}\n", _with2.HiddenSectors);

                                  break;

          

                              case PARTITION_STYLE.GPT:

                                  var _with3 = _with1.Gpt;

                                  Console.WriteLine("\r\t  PartitionType  {0}\n", _with3.PartitionType);

                                  Console.WriteLine("\r\t  PartitionId    {0}\n", _with3.PartitionId);

                                  Console.WriteLine("\r\t  Name           {0}\n", _with3.Name);

                                  break;

          

                              case PARTITION_STYLE.RAW:

                                  Console.WriteLine("RAW!");

                                  break;

          

                              default:

                                  Console.WriteLine("Unknown!");

                                  break;

                          }

                      }

                  }

              }

          }  

"@

    

 

          

    Write-Log -Message "[Check if Add-Type has already been run]" INFO    

    If ("PartitionFinder.IOCtl" -as [type]) {

    }

    Else {

        Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source -Verbose -ErrorAction Continue

    }

          

              

    Write-Log -Message "[Get all disks connected to Cluster Node]" INFO        

    $d = Get-WmiObject -ErrorAction Stop -Namespace root\wmi ClusPortDeviceInformation | Where-Object { $_.ConnectedNode -like $ServerName }

          

    If ($d -eq $null) {

        throw 'ERROR: system does not appear to be a Storage Spaces Direct node.'

    }

          

    

    Write-Log -Message "[Filter Disks from Cluster to ensure non Virtual\Default]" INFO    

    # filter to non-default (0) non-virtual (0x1) devices; actually a bitmask

    $filteredDisks = $d | Sort-Object ConnectedNode, ConnectedNodeDeviceNumber | Where-Object {

        # non-default (enclosure) and non-virtual devices

        $_.DeviceAttribute -and -not ($_.DeviceAttribute -band 0x1) } 

 

    Write-Log -Message $filteredDisks OUTPUT

 

    Write-Log -Message "[Get Storage Spaces Partition Info for Cluster Node disks]" INFO  

    ForEach ($disk in $filteredDisks) {

          

        $oldOut = [Console]::Out

        $newOut = New-Object IO.StringWriter

          

        try {

            [Console]::SetOut($newOut)

            [PartitionFinder.IOCtl]::SendIoCtlDiskGetDriveLayoutEx($disk.DeviceNumber)

        }

          

        finally {

            [Console]::SetOut($oldOut)

        }

          

          

        $output = $newOut.ToString()

        $parts = $output.Split([Environment]::NewLine) | ForEach-Object {

            # PartitionType and Name are paired for every partition, in this order

            If ($_ -match 'PartitionType\s+(.*)$') {

                # be willing to handle partitions which diskutil does not name

                If ($ptype -ne $null) {

                    Get-PartitionType $ptype

                }

                $ptype = $matches[1]

            }

            ElseIf ($_ -match 'Name\s+(.*)$') {

                Get-PartitionType $ptype $matches[1]

                $ptype = $null

            }

        }

        $disk | Add-Member -NotePropertyName Partitions -NotePropertyValue $parts -PassThru | Out-Null

    }

          

 

    Write-Log -Message "[Get PNP OS Disk Information]" INFO  

    Write-Log -Message "[Ensuring OS Disk Are Excluded]"  INFO

    Get-WmiObject Win32_LogicalDisk -Filter $Filter | ForEach-Object {

        $Partition = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$($_.DeviceID)'} WHERE AssocClass = Win32_LogicalDiskToPartition" | Select-Object * -Exclude __*

        $OSDiskPNPs += ((Get-WmiObject Win32_DiskDrive -Filter "Index=$($Partition.DiskIndex)") | Where-Object { $_.pnpdeviceid -notmatch "VIRT" }).pnpdeviceid

    }

    

    

    Write-Log -Message "[Get all disks connected and DR number except OS and Virtual]" INFO  

    Write-Log -Message "[Getting DR Numbers from registry]"  INFO

    $Path = "HKLM:\SYSTEM\CurrentControlSet\Services\disk\enum"

    $DRDisks = (Get-ItemProperty $path).psobject.properties | Where-Object { $_.name -notmatch 'Count|NextInstance|PS*' -and $OSDiskPNPs -notcontains $_.value }   | Select-Object name, value

    Write-Log -Message $DRDisks OUTPUT

 

 

    Write-Log -Message "[Getting All Disks Connected To Node]" INFO

    $PDdisks = Get-StorageNode -name "$servername*"  | Get-PhysicalDisk -PhysicallyConnected  | Where-Object { $_.FriendlyName -notmatch 'LOGICAL VOLUME|Msft' }

    Write-Log -Message $PDdisks OUTPUT 

 

    

    Write-Log -Message "[Getting Storage Nodes]" INFO

    $Storagenode = (get-storagenode | Where-Object { $_.name -like "$ServerName*" } | get-unique) 

    Write-Log -Message $StorageNode OUTPUT

 

 

    Write-Log -Message "[Get attached Storage Enclosures to Node]" INFO  

    $StorageEnclosures = get-storagenode -name $storagenode.name | Get-StorageEnclosure -PhysicallyConnected | Get-Unique

    Write-Log -Message $StorageEnclosures OUTPUT

 

    

    Write-Log -Message "[Get all attached disks to use for Storage Spaces by PNP]" INFO  

    $PNPEnclosures = (Get-PnpDevice -class SCSIAdapter | where-object { $_.instanceid -like "PCI*" -and $_.Friendlyname -notlike "*RAID*" }).Instanceid

    Write-Log -Message $PNPEnclosures OUTPUT

    $PNPDisksonEnc = (Get-pnpdevice -instanceid $PNPEnclosures | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_children).data | where-object { $OSDiskPNPs -notcontains $_ -and $_ -notmatch "Virtual|Enclosure|Dummy|SCSI_COMMUNICATE|LOGICAL_VOLUME" }

    Write-Log -Message $PNPDisksonEnc OUTPUT

 

 

    Write-Log -Message "[Attach Storage Spaces information to Partition Information]" INFO  

    ForEach ($Disk in $filteredDisks) {

 

        Write-Log -Message $Disk OUTPUT

 

        $DiskPartitions = "" | Select-Object  Node, DR, Model, SerialNumber, Usage, Slot, Media, OpSt, FW, Health, Partitions, PNPId, PDID, VirtDskFoot, 'R/M', 'R/T', Cache, SBLAttribute, SBLDiskCacheState, SBLCacheUsageCurrent, SBLCacheUsageDesired, EventLog, Controller, LostDisks

        $DiskPartitions.Node = $Disk.ConnectedNode       

        $DiskPartitions.DR = $Disk.ConnectedNodeDeviceNumber       

    

               

        $SerialDisk = ($PDdisks | Where-Object { $_.Serialnumber -like $Disk.SerialNumber.trim() })

        Write-Log -Message "PDDisk Match $SerialDisk" OUTPUT

 

        Write-Log -Message "Checking if NVMe and Adapter s" OUTPUT

        If ($SerialDisk.BusType -match "NVMe" -and $SerialDisk.AdapterSerialNumber -notmatch $null ) {

            $DiskPartitions.SerialNumber = $SerialDisk.AdapterSerialNumber

            Write-Log -Message "NVMe Adapter Serial Number for disk detected $SerialDisk.AdapterSerialNumber" OUTPUT

        }

        else {

            $DiskPartitions.SerialNumber = $SerialDisk.SerialNumber

            Write-Log -Message "NVMe disk either detected and Adapter Serial not found or not NVMe:  $SerialDisk.SerialNumber" OUTPUT

        }

        

        $DiskPartitions.Model = $SerialDisk.Model

        $DiskPartitions.Usage = $SerialDisk.Usage

        $DiskPartitions.Slot = $SerialDisk.SlotNumber

        $DiskPartitions.Media = $SerialDisk.MediaType

        $DiskPartitions.OpSt = $SerialDisk.OperationalStatus

        $DiskPartitions.FW = $SerialDisk.FirmwareVersion

        $DiskPartitions.Health = $SerialDisk.HealthStatus

        $DiskPartitions.Partitions = ($Disk.Partitions -join ', ')

        $DiskPartitions.PNPId = (($DRDisks | Where-Object { $_.Name -eq $Disk.ConnectedNodeDeviceNumber }).Value)

        $DiskPartitions.PDID = $Disk.DeviceGuid

        $DiskPartitions.VirtDskFoot = ($PDdisks | Where-Object { ($_.Serialnumber -like $Disk.SerialNumber.trim()) -and ($_.MediaType -ne "SSD" -and $_.MediaType -ne 'Unspecified') } | select-Object @{N = 'Percentage' ; E = { ([math]::Round($_.Virtualdiskfootprint) / ($_.Size)).tostring("P") } }).Percentage

          

        If ($PDdisks | Where-Object { $_.Serialnumber -like $Disk.SerialNumber.trim() -and $_.MediaType -match 'SSD' -and $_.Usage -like 'Journal' }) {

            $DiskPartitions.'R/M' = (Get-Counter -counter "\Cluster Storage Cache Stores($($Disk.ConnectedNodeDeviceNumber))\Read Errors Media").countersamples.cookedvalue 

            $DiskPartitions.'R/T' = (Get-Counter -counter "\Cluster Storage Cache Stores($($Disk.ConnectedNodeDeviceNumber))\Read Errors Total").countersamples.cookedvalue 

        }

        Else {

 

            $DiskPartitions.Cache = ((get-counter -ListSet 'Cluster Storage Hybrid Disks' -ErrorAction SilentlyContinue).PathsWithInstances  | where-object { $_ -like '*Disk Transfers/sec*' -and $_ -like "\Cluster Storage Hybrid Disks($($Disk.ConnectedNodeDeviceNumber):*" }).replace('\ClusterStorage Hybrid Disks', '').replace('\Disk Transfers/sec', '')  

        }

           

        $Items = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\ClusBFlt\Parameters\Disks\$($Disk.Deviceguid)" | Get-ItemProperty | Select-Object SblTargetMgrAttributes, DiskCacheState, CacheUsageCurrent, CacheUsageDesired  

        Write-Log -Message $Items OUTPUT

        $DiskPartitions.SBLAttribute = $Items.SblTargetMgrAttributes | Where-Object { $_ -ne $null }

        $DiskPartitions.SBLDiskCacheState = $Items.DiskCacheState | Where-Object { $_ -ne $null }

        $DiskPartitions.SBLCacheUsageCurrent = $Items.CacheUsageCurrent | Where-Object { $_ -ne $null }

        $DiskPartitions.SBLCacheUsageDesired = $Items.CacheUsageDesired | Where-Object { $_ -ne $null } 

 

           

        if ($SerialDisk.HealthStatus -notmatch "Healthy") {

            $LogName = 'System'

            $Source = 'Disk'

            $Event = Get-WinEvent  -filterhashtable  @{LogName = $LogName; ProviderName = $Source ; Data = $Disk.ConnectedNodeDeviceNumber } -ErrorAction SilentlyContinue | Select-Object -last 3 | out-string

        

            If ($Event) {

                $DiskPartitions.EventLog = $Event

            }

            Else {

                $DiskPartitions.EventLog = "No Events Found"

            }

        }

        $DiskPartitions.Controller = (Get-pnpdevice (get-pnpdevice -instanceid $($DiskPartitions.PNPId) | Get-PnpDeviceProperty -keyname DEVPKEY_Device_Parent).Data).FriendlyName    

        $DiskPartitions.LostDisks = $SerialDisk | Where-Object { $_.Opst -match "Lost Communication" } | Select-Object SerialNumber, MediaType, Slot, DR, OpSt, Health, PNPid , ServerName, R/M, R/T

        Write-Log -Message $DiskPartitions OUTPUT

        $DiskData += $DiskPartitions

        Clear-Variable Serial -ErrorAction SilentlyContinue

    }

    

 

    if ($ServerName -match $ClusterOwnerNode) {

 

        Write-Log -Message "[Get BIOS Information]" INFO  

        $BIOSInfo = Get-ciminstance win32_bios | Select-Object Manufacturer, Status, SMBIOSMajorVersion, SMBiosMinorVersion, SystemBiosMajorVersion, SystemBiosMinorVersion

        $allRecords["Storage Health"].Add(("Bios Information"), (@{Output = $BIOSInfo }))

 

 

        Write-Log -Message "[Get Model Information from WMI]" INFO  

        $CompSysInfo = (Get-WmiObject -Class:Win32_ComputerSystem).Model

        $allRecords["Storage Health"].Add(("Model"), (@{Output = $CompSysInfo }))

 

 

        Write-Log -Message "[Getting Unhealhy Storage Pool Details]" INFO

        $allRecords["Storage Health"].Add(("Storage Pool"), (@{Output = Get-StoragePool | Where-Object { $_.HealthStatus -notlike 'Healthy' } }))

        Write-Log -Message $allRecords.'Storage Health'.'Storage Pool'.Output OUTPUT

 

 

        Write-Log -Message "[Getting Unhealthy Virtual Disk In Non-Healthy State]" INFO  

        $allRecords["Storage Health"].Add(("Virtual Disk"), (@{Output = Get-VirtualDisk | Where-Object { $_.HealthStatus -ne 'Healthy' } }))

        Write-Log -Message $allRecords.'Storage Health'.'Virtual Disk'.Output OUTPUT

 

 

        Write-Log -Message "[Getting Any Running Storage Jobs]" INFO

        $allRecords["Storage Health"].Add(("Storage Jobs"), (@{Output = Get-StorageJob | Where-Object { $_.JobState -ne 'Completed' } }))

        Write-Log -Message $allRecords.'Storage Health'.'Storage Jobs'.Output OUTPUT 

 

 

        Write-Log -Message "[Getting Cluster Nodes Where State Not Up]" INFO

        $allRecords["Storage Health"].Add(("Cluster Nodes"), (@{Output = Get-ClusterNode | where-object { $_.State -notlike 'Up' } | Select-Object Name, State }))

        Write-Log -Message $allRecords.'Storage Health'.'Cluster Nodes'.Output OUTPUT

        

 

        Write-Log -Message "[Getting Cluster Shared Volumes Not Online]" INFO

        $allRecords["Storage Health"].Add(("CSV"), (@{Output = Get-ClusterSharedVolume  | Where-Object { $_.State -NotLike "Online" } }))

        Write-Log -Message $allRecords.'Storage Health'.'CSV'.Output OUTPUT

    

 

        Write-Log -Message "[Getting Storage Enclosures In Unhealthy State]" INFO

        $allRecords["Storage Health"].Add(("Enclosures"), (@{Output = Get-StorageEnclosure | Where-Object { $_.HealthStatus -notmatch "Healthy" } | Select-Object FriendlyName, SerialNumber, OperationalStatus, HealthStatus, NumberOfSlots, ObjectId, ElementsTypesInError }))

        Write-Log -Message $allRecords.'Storage Health'.'Enclosures'.Output OUTPUT

        

 

        Write-Log -Message "[Getting Storage Enclosures SNV In Unhealthy State]" INFO

        $allRecords["Storage Health"].Add(("EnclosureSNV"), (@{Output = Get-StorageEnclosureSNV | Where-Object { $_.IsPhysicallyConnected -match "True" } | Select-Object Storagenodeobjectid, StorageenclosureObjectid }))

        Write-Log -Message $allRecords.'Storage Health'.'EnclosureSNV'.Output OUTPUT

     

                

        Write-Log -Message "[Getting Health Actions In Not succeeded  State]" INFO

        $allRecords["Storage Health"].Add(("Storage Health Action"), (@{Output = Get-StorageSubSystem cluster* | Get-StorageHealthAction | Where-Object { $_.State -ne 'Succeeded' } }))

        Write-Log -Message "$allRecords.'Storage Health'.'Storage Health Action'.Output OUTPUT"

        

        

        Write-Log -Message "[Getting Non Primordial Storage Pools Disks]" INFO

        $allRecords["Storage Health"].Add(("Storage Pool Disks"), (@{Output = (Get-StoragePool -IsPrimordial $false | Get-PhysicalDisk).SerialNumber | Sort-Object $_ }))

        Write-Log -Message $allRecords.'Storage Health'.'Storage Pool Disks'.Output OUTPUT

                     

        

        Write-Log -Message "[Getting All Cluster Disks]" INFO

        $allRecords["Storage Health"].Add(("Cluster Disks"), (@{Output = Get-physicaldisk | Where-Object { ($_.Friendlyname -notlike 'Msft Virtual Disk') -and ($_.Friendlyname -notlike '*LOGICAL VOLUME') -and ($_.Friendlyname -notlike '*ServeRAID*') -and ($_.Friendlyname -notlike '*LSI MegaSR*') } | Sort-Object SerialNumber }))

        Write-Log -Message ($allRecords.'Storage Health'.'Cluster Disks'.Output) OUTPUT

        

 

        Write-Log -Message "[Checking For Problems With The Storage Subsystem]" INFO

        $allRecords["Storage Health"].Add(("Current Faults"), (@{Output = Get-StorageSubSystem -FriendlyName cl* | Debug-StorageSubSystem }))

        Write-Log -Message $allRecords.'Storage Health'.'Current Faults'.Output OUTPUT

                    

        

        Write-Log -Message "[Disks Not In Pool]" INFO

        $allRecords["Storage Health"].Add(("Disks Not In Pool"), (@{Output = (Compare-Object $allRecords.'storage health'.'cluster disks'.output.SerialNumber $allRecords.'storage health'.'Storage Pool Disks'.Output | where-object { $_.SideIndicator -like '=>' }).InputObject }))

        Write-Log -Message $allRecords.'Storage Health'.'Disks Not In Pool'.Output  OUTPUT

 

    }

 

    Write-Log -Message "[Check disks connected via PNP eligible for adding and compare to disks in Storage Spaces - $ServerName]" INFO  

    $MissingDisks = (Compare-Object $($DiskData.pnpid) $PNPDisksonEnc | where-object { $_.SideIndicator -like '=>' }).InputObject

    

 

    Write-Log -Message "[Checking if Disk is missing for PNP Information]" INFO  

    If ($MissingDisks) {

        Foreach ($MissingDisk in $MissingDisks) {

            $PNPLostData = Get-PnpDeviceProperty -InstanceId $MissingDisk -KeyName DEVPKEY_Device_InstanceId , DEVPKEY_Device_LastArrivalDate, DEVPKEY_Device_IsPresent , DEVPKEY_Device_HasProblem, DEVPKEY_Device_ProblemCode , DEVPKEY_Device_DevNodeStatus-ErrorAction SilentlyContinue

            #Getting PNP details for lost disk

            $PNPLostDisk = "" | Select-Object  InstanceId , LastArrivalDate, IsPresent, HasProblem, ProblemCode , DevNodeStatus

            $PNPLostDisk.InstanceId = $PNPLostData.Data[0]

            $PNPLostDisk.LastArrivalDate = $PNPLostData.Data[1]

            $PNPLostDisk.IsPresent = $PNPLostData.Data[2]

            $PNPLostDisk.HasProblem = $PNPLostData.Data[3]

            $PNPLostDisk.ProblemCode = $PNPLostData.Data[4]

            $PNPLostDisk.DevNodeStatus = $PNPLostData.Data[5]

            $PNPLostDisks += $PNPLostDisk

        }

    }

 

 

    Write-Log -Message "[Adding any missing Disks found]" INFO

    $allRecords["Storage Health"].Add(("Missing Disks"), (@{Output = $PNPLostDisks }))

    Write-Log -Message $allRecords.'Storage Health'.'Missing Disks'.Output  OUTPUT

 

 

    Write-Log -Message "[Health Service Running]" INFO

    $allRecords["Storage Health"]["Health Running"] += $Healthrunning

    Write-Log -Message $allRecords.'Storage Health'.'Health Running' OUTPUT

 

 

    Write-Log -Message "[Write All Data needed to Hashtable]" INFO

    $DiskCheck += $allRecords

    $DiskCheck['DiskHealth'] += $DiskData

 

 

    Write-Log -Message "[Check if Verbose Output is required]" INFO

    if ($LoggingLevel -match "V") {

        # Move the files from $DataColLog to $DataCollectionDir for collection

        Move-Item -Path $DataColLog -Destination $DataCollectionDir -Verbose

    }

 

    

    Write-Log -Message "[Returning data from Invoke-command to Result Variable]" INFO

    Return $DiskCheck

}-Args $WriteLogDef, $GetPartitionTypeDef, $GetLogPaths, $LoggingLevel, $ClusterOwnerNode

 

 

Write-Log -Message "[Output data in order of node name]" INFO

Write-Log -Message "[Format data into readable text]" INFO

$MappedData = Read-DataMapper $Result

$CollectedServers = ($Result.'DiskHealth' | Select-Object Node -Unique).Node | Sort-Object $_

ForEach ($CollectedServer in $CollectedServers) {

    Write-Host `n

    Write-Host `n

    Write-Host $CollectedServer : -ForegroundColor Yellow

    Write-Host "SSD Count: " -NoNewline

    ($MappedData | where-object { $_.Node -like $CollectedServer -and $_.Media -like "SSD" }).count

    Write-Host "HDD Count: " -NoNewline

    ($MappedData | where-object { $_.Node -like $CollectedServer -and $_.Media -like "HDD" }).count

   ($MappedData | where-object { $_.Node -like $CollectedServer }) | Sort-Object Slot | Format-Table  Serialnumber, Usage, Media, FW, Model, Health, Opst, R/M, R/T, Slot, DR, Cache, SBLAttribute, SBLDiskCacheState, SBLCacheUsageCurrent, VirtDskFoot -AutoSize -force  | out-string -Width 4000 

}

 

Write-Log -Message "[Getting bad disk data]" INFO

$BadDisks = $MappedData | Where-Object { ($_.SBLAttribute -notmatch 'Default') -or ($_.SBLDiskCacheState -notmatch 'CacheDiskStateInitializedAndBound') -and ($_.Serialnumer -notmatch $null) }  | Select-Object SerialNumber, Health, Opst, SBLDiskCacheState, SBLAttribute, Slot, DR, Media, ServerName  

 

 

#===================================================================

# Check Data:

#===================================================================

 

 

Write-Host "`n"

Write-Host "Hardware details:" -ForegroundColor Yellow

Write-Host "`n"

$Result.'Storage Health'.'Model'.Output

$Result.'Storage Health'.'Bios Information'.Output

 

 

Write-Host "`n"

Write-Host "Storage Diag $Version : Checking Against Known Issues" -ForegroundColor Yellow

Write-Host "`n"

 

 

Write-Log -Message "[Checks for all disks picked up in OS that are not in Storage spaces]" INFO

If ($Result.'DiskHealth'.Lostdisks.pnpid) {

    Write-Color "Non Communicating Disks".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White  

    $StorageCheck["Validation"]["Non Communicating Disks"] = "1" 

}

Else {

    Write-Color "Non Communicating Disks".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White 

}

 

 

Write-Log -Message "[Checks for SBL Bad Disks]" INFO

If ($BadDisks) { 

    Write-Color "SBL Disk Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White  

    $StorageCheck["Validation"]["SBL Disk Check"] = "1" 

}

Else {

    Write-Color "SBL Disk Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

 

 

Write-Log -Message "[Check for disks only seen in OS]" INFO

If ($null -eq $Result.'Storage Health'.'Missing Disks'.output.mInstanceid) {

    Write-Color "Missing Disks From Storage Spaces".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Missing Disks From Storage Spaces".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White  

    $StorageCheck["Validation"]["Missing Disks From Storage Spaces"] = "1" 

}

 

 

Write-Log -Message "[Check for Unhealthy Storage Pool]" INFO

If ($Result.'Storage Health'.'Storage Pool'.output.Friendlyname) {

    Write-Color "Storage Pool Health Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White

    $StorageCheck["Validation"]["Storage Pool Health Check"] = "1" 

}

Else {

    Write-Color "Storage Pool Health Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White   

}

 

 

Write-Log -Message "[Check for Health Process not running]" INFO

If ( $Result.'Storage Health'.'Health Running'.Output.count -lt $Nodes.count) {

    Write-Color "Cluster Nodes Health Process Running".PadRight(50), '[', ' FAIL ', ']'  -ForeGroundColor White, White, Red, White   

    $StorageCheck["Validation"]["Cluster Nodes Health Process Running"] = "1" 

}

Else {

    Write-Color "Cluster Nodes Health Process Running".PadRight(50), '[', ' PASS ', ']'  -ForeGroundColor White, White, Green, White

}

  

 

Write-Log -Message "[Disks in state other than healthy]" INFO

If ($Result.'DiskHealth'.'Health' -notlike 'Healthy') {

    Write-Color "Disk Health Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Disk Health Check"] = "1" 

}

Else {

    Write-Color "Disk Health Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

 

 

Write-Log -Message "[Check for Virtual Disks in bad state]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Virtual Disk'.output)) {

    Write-Color "Virtual Disk Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Virtual Disk Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Virtual Disk Check"] = "1" 

}

 

 

Write-Log -Message "[Check For Disks In Transient State]" INFO

If ($Result.'DiskHealth'.'Opst' -like "Transient Error") {

    Write-Color "Transient Disk Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Transient Disk Check"] = "1" 

}

Else {

    Write-Color "Transient Disk Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

 

 

Write-Log -Message "[Check For Storage Jobs]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Storage Jobs'.output)) {

    Write-Color "Storage Job Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Storage Job Check".PadRight(50), '[', ' WARN ', ']' -ForeGroundColor White, White, Yellow, White 

    $StorageCheck["Validation"]["Storage Job Check"] = "1" 

}

 

 

Write-Log -Message "[Cluster Node Check]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Cluster Nodes'.output)) {

    Write-Color "Cluster Node Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Cluster Node Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Cluster Node Check"] = "1" 

}

 

 

Write-Log -Message "[Cluster Shared Volumes Check]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'CSV'.Output )) {

    Write-Color "Cluster Shared Volumes Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Cluster Shared Volumes Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Cluster Shared Volumes Check"] = "1" 

}

 

 

Write-Log -Message "[Storage Enclosure Check]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Enclosures'.output)) {

    Write-color "Storage Enclosure Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Storage Enclosure Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Storage Enclosure Check"] = "1" 

}

 

 

Write-Log -Message "[Check for Storage Subsystem Alert]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Current Faults'.output)) {

    Write-Color "Storage Subsystem Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Storage Subsystem Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Storage Subsystem Check"] = "1" 

}

 

 

Write-Log -Message "[Check for health-related system activities for Storage subsystems,  file shares, and volumes]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Storage Health Action'.output)) {

    Write-Color "Storage Health Action Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Storage Health Action Check".PadRight(50), '[', ' WARN ', ']' -ForeGroundColor White, White, Yellow, white 

    $StorageCheck["Validation"]["Storage Health Action Check"] = "1" 

}

 

 

Write-Log -Message "[Check for corrupt\missing partitions]" INFO

If ($Result.DiskHealth  | Where-Object { $_.Partitions -notlike "*Clus|Microsoft SBL Cache Store], Space Protective*" -and $_.Partitions -notlike "*Clus|Microsoft SBL Cache Hdd], Space Protective*" } ) {

    Write-Color "Storage Spaces Partitions Check".PadRight(50), '[', ' FAIL ', ']' -ForeGroundColor White, White, Red, White 

    $StorageCheck["Validation"]["Storage Spaces Partitions Check"] = "1" 

}

Else {

    Write-Color "Storage Spaces Partitions Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

 

 

Write-Log -Message "[Check for disks not in non primordial pool]" INFO

If ([string]::IsNullorEmpty($Result.'Storage Health'.'Disks Not In Pool'.output)) {

    Write-Color "Disks Not In Pool Check".PadRight(50), '[', ' PASS ', ']' -ForeGroundColor White, White, Green, White

}

Else {

    Write-Color "Disks Not In Pool Check".PadRight(50), '[', ' WARN ', ']' -ForeGroundColor White, White, Yellow, white 

    $StorageCheck["Validation"]["Disks Not In Pool Check"] = "1" 

}

 

 

#===================================================================

# Data Output:

#===================================================================

 

 

Write-Log -Message "[Check for disks in lost communication state and if they are connected to OS]" INFO

If ($StorageCheck.Validation."Non Communicating Disks") {

    Write-Host "`n"

    Write-Host "These disks have lost communication with Storage Spaces, checking if OS can see them:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.DiskHealth.Lostdisks | Format-Table

    Write-Host "Disk Status in OS" -ForegroundColor Cyan

    if ($Result.DiskHealth.LostDisks.PNPId) {

        Foreach ($PNPIdLostdisk in $Result.DiskHealth.Lostdisks) {

            $PNPLostData = Get-PnpDeviceProperty -InstanceId *$($PNPidLostdisk.pnpid)* -KeyName DEVPKEY_Device_InstanceId , DEVPKEY_Device_LastArrivalDate, DEVPKEY_Device_IsPresent , DEVPKEY_Device_HasProblem, DEVPKEY_Device_ProblemCode, DEVPKEY_Device_DevNodeStatus -ErrorAction SilentlyContinue

            #Getting PNP details for lost disk

            $PNPLostDisk = "" | Select-Object  InstanceId , LastArrivalDate, IsPresent, HasProblem, ProblemCode , DevNodeStatus

            $PNPLostDisk.InstanceId = $PNPLostData.Data[0]

            $PNPLostDisk.LastArrivalDate = $PNPLostData.Data[1]

            $PNPLostDisk.IsPresent = $PNPLostData.Data[2]

            $PNPLostDisk.HasProblem = $PNPLostData.Data[3]

            $PNPLostDisk.ProblemCode = $PNPLostData.Data[4]

            $PNPLostDisk.DevNodeStatus = $PNPLostData.Data[5]

            $PNPLostDisks += $PNPLostDisk

        }

    }

}

 

 

Write-Log -Message "[Data Output for SBL baddisks]" INFO

If ($StorageCheck.Validation."SBL Disk Check") { 

    Write-Host "`n"

    Write-Host "These disks are in an unexpected state in SBL :" -ForegroundColor Cyan

    $Baddisks | Select-Object SerialNumber, Health, Opst, SBLDiskCacheState, SBLAttribute, Slot, DR, Media, Node | Format-Table -AutoSize

}

 

 

Write-Log -Message "[Data Output for disks only seen in OS]" INFO

If ($StorageCheck.Validation."Missing Disks From Storage Spaces") {

    Write-Host "`n"

    Write-Host "Disks are not seen correctly in storage spaces, checking if OS can see them connected :" -ForegroundColor Cyan

    $Result.'Storage Health'.'Missing Disks'.Output | format-table -AutoSize

}

 

 

Write-Log -Message "[Data Output for Storage Pools in bad state]" INFO

If ($StorageCheck.Validation."Storage Pool Health Check") {

    Write-Host "`n"

    Write-Host "You have unhealthy Storage Pools :" -ForegroundColor Cyan

    $Result.'Storage Health'.'Storage Pool'.output | Format-Table

}

 

 

Write-Log -Message "[Data Output for Health Process not running]" INFO

If ($StorageCheck.Validation."Cluster Nodes Health Process Running") {

    Write-Host "`n"

    Write-Host "Health Process is not running on all nodes :" -ForegroundColor Cyan

    $Result.'Storage Health'.'Health Running' | sort-object ServerName | Format-Table

}

 

 

Write-Log -Message "[Data Output for Disks in state other than healthy]" INFO

If ($StorageCheck.Validation."Disk Health Check") {

    Write-Host "`n"

    Write-Host "Unhealthy Disks :" -ForegroundColor Cyan

    $Result.'DiskHealth' | Where-Object { $_.Health -notlike 'Healthy' -or $_.Opst -notmatch "OK" -and $_.SerialNumber -ne $null } | Format-Table SerialNumber, Media, Health, OpSt, Cache, Slot, DR, SBLDiskCacheState, SBLCacheUsageCurrent, SBLCacheUsageDesired, Node -AutoSize -Force | out-string -Width 4000 

    Write-Host "Checking Event Log entries for unhealthy disks references:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'DiskHealth'.EventLog | Format-Table

}

 

 

Write-Log -Message "[Check for Virtual Disks in bad state]" INFO

If ($StorageCheck.Validation."Virtual Disk Check") {

 

    Write-Host `n    

    Write-Host "Unhealthy Virtual Disks:" -ForegroundColor Cyan

    Write-host ($Result.'Storage Health'.'Virtual Disk'.output | out-string)

    

    invoke-command $ClusterName {

        Param( $WriteLogDef )

        . ([ScriptBlock]::Create($WriteLogDef))

 

        ForEach ($Unhealthy in $Using:Result.'Storage Health'.'Virtual Disk'.Output | Where-Object { $_.OperationalStatus -match '53251*|3*|11*' }) {

            $VirtualDisk = get-virtualdisk -FriendlyName $Unhealthy.Friendlyname

 

            Write-Host `n

            Write-Host $VirtualDisk.FriendlyName OperationalStatus: $VirtualDisk.OperationalStatus HealthStatus: $VirtualDisk.HealthStatus -ForegroundColor cyan

            Write-Host `n 

            

            # Running as job because cmdlet get-physicalextent doesn't filter before pulling data back wheen using CIM method GetPhysicalExtent

            $TimeoutSeconds = 20

            $ScriptBlock = {                           

                Get-PhysicalExtent -Virtualdisk $Args[0] | where-object { $_.OperationalStatus -notlike 'Active' }  | sort-object PhysicalDiskUniqueId, OperationalStatus -unique }

  

            $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $VirtualDisk

            If (Wait-Job $Job -Timeout $TimeoutSeconds) { $JobOutput = Receive-Job $Job }

 

            Remove-Job -force $Job

 

            If ($JobOutput) {

                $JobOutput | Select-Object PhysicalDiskUniqueId, OperationalStatus | Format-Table  

                $UniqueDisks = $JobOutput | sort-object PhysicalDiskUniqueId -unique

                # This has to come from physical disk to ensure cables were not swapped

                $VDIssue = Get-PhysicalDisk | Where-Object { $UniqueDisks.PhysicalDiskUniqueId -contains $_.Uniqueid } | Select-Object SerialNumber, Uniqueid, SlotNumber

                ($using:Result.'DiskHealth' | Where-Object { $VDIssue.SerialNumber -contains $_.SerialNumber }) | Select-Object SerialNumber, ServerName, Diskid -ExcludeProperty Runspaceid, PSComputerName | Format-Table

                $VDIssue | Format-Table

            }

            Else {

                Write-Host "Unable to retrieve Physical Extents within timeout period of $TimeoutSeconds seconds, this is indicative of node down or too many disks in unhealthy state or missing" -ForegroundColor Yellow

            }

            Clear-Variable JobOutput -ErrorAction SilentlyContinue

        }

    }

}

 

 

Write-Log -Message "[Data Output For Disks In Transient State]" INFO

If ($StorageCheck.Validation."Transient Disk Check") {

    Write-Host "`n"

    Write-Host "Disks In Transient State :" -ForegroundColor Cyan

    $Result.'DiskHealth' | Where-Object { $_.Opst -like "Transient Error" } | Format-Table SerialNumber, Usage, Media, FW, Model, Health, Node -AutoSize

    Write-Host "`n"

}

 

 

Write-Log -Message "[Data Output For Storage Jobs]" INFO

If ($StorageCheck.Validation."Storage Job Check") {

    Write-Host "`n"

    Write-Host "There are Storage Jobs please review:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'Storage Health'.'Storage Jobs'.Output | Format-List Name, IsBackgroundTask, ElapsedTime, JobState, PercentComplete, BytesProcessed, BytesTotal

}

 

 

Write-Log -Message "[Data Output For Cluster Node]" INFO

If ($StorageCheck.Validation."Cluster Node Check") {

    Write-Host "`n"

    Write-Host "There are Cluster Nodes in a non-active state:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'Storage Health'.'Cluster Nodes'.Output | Format-Table

}

 

 

Write-Log -Message "[Data Output For Cluster Shared Volumes]" INFO

If ($StorageCheck.Validation."Cluster Shared Volumes Check") {

    Write-Host "`n"

    Write-Host "There are Cluster Shared Volumes with Problems, please review data:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'Storage Health'.'CSV'.Output | Format-List

}

 

 

Write-Log -Message "[Data Output For Storage Enclosure Check]" INFO

If ($StorageCheck.Validation."Storage Enclosure Check") {

    Write-Host "`n"

    Write-Host "There are Storage Enclosure problems, please review data:" -ForegroundColor Cyan

    Write-Host "`n"

 

    Foreach ($Enclosure in $Result.'Storage Health'.'Enclosures'.Output) {

        $SE = [regex]::Match($Enclosure.objectid, 'SE:{(.*?)}').Groups[1].Value 

        $SNV = ($Result.'Storage Health'.'EnclosureSNV'.Output | Where-Object { $_.StorageEnclosureObjectId -match $SE }).StorageNodeObjectId

        [regex]::match($SNV, 'SN:(.*?)"').Groups[1].Value 

        $Enclosure | Format-Table FriendlyName, SerialNumber, OperationalStatus, HealthStatus, NumberOfSlots

    }

}

 

 

Write-Log -Message "[Data Output For Storage Subsystem Check]" INFO

If ($StorageCheck.Validation."Storage Subsystem Check") {

    Write-Host "`n"

    Write-Host "There Storage Subsystem problems, please review data:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'Storage Health'.'Current Faults'.Output | Format-List

}

 

 

Write-Log -Message "[Data Output For Storage Health Action Check]" INFO

If ($StorageCheck.Validation."Storage Health Action Check") {

    Write-Host "`n"

    Write-Host "There Storage Health Actions in progress, please review data:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'Storage Health'.'Storage Health Action'.Output | Format-table Reason, State, Percentcomplete, uniqueid

}

 

 

Write-Log -Message "[Data Output For Storage Spaces Partitions Check]" INFO

If ($StorageCheck.Validation."Storage Spaces Partitions Check") {

    Write-Host "`n"

    Write-Host "There Storage Spaces Partitions that look to be incorrect and can result in disk errors such as transient disks, please review data:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.DiskHealth | Where-Object { $_.Partitions -notlike "*Clus|Microsoft SBL Cache Store], Space Protective*" -and $_.Partitions -notlike "*Clus|Microsoft SBL Cache Hdd], Space Protective*" } | Format-Table Node, DR, Model, SerialNumber, Partitions -AutoSize

}

 

 

Write-Log -Message "[Data Output For Storage Spaces Disks In Pool Check]" INFO

If ($StorageCheck.Validation."Disks Not In Pool Check") {

    Write-Host "`n"

    Write-Host "There Physical Disks that are not in the Non Primordial Pool:" -ForegroundColor Cyan

    Write-Host "`n"

    $Result.'Storage Health'.'Disks Not In Pool'.Output | Format-List

}

 

 

Write-Log -Message "[Spaces to ensure report leaves spaces between verbose output]" INFO

Write-Host `n

Write-Host `n

 

 

Write-Log -Message "[Collect data from nodes in cluster and compress]" INFO

Get-Results 

 

 

Write-Log -Message "[Clear Result]" INFO

Clear-Variable Result, LoggingLevel -ErrorAction SilentlyContinue

 
