# Script to find the VMCX, VMRS file location for all the VMs at the same time.

# Import the Hyper-V module
Import-Module Hyper-V

# Set the default path for the VM location
#Set-VMHost -VirtualMachinePath 'C:\ClusterStorage\Volume2'

# Define a function to recursively find files with a specific extension
function Find-Files($path, $extension) {
    Get-ChildItem -Path $path -Filter "*.$extension" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        return $_.FullName
    }
}

# Get the default path for VM files
$vmFilesPath = (Get-VMHost).VirtualMachinePath

# Loop through each VM
foreach ($vm in (Get-VM)) {
    # Print the VM's name
    Write-Output "VM Name: $($vm.Name)"
 
    # Get VM configuration file path
    $vmFilesPath = (Get-VM).ConfigurationLocation
 

    # Find and print the path of the VMCX file
    $vmcxFilePath = Find-Files -path $vmFilesPath -extension "vmcx" | Where-Object { $_ -like "*$($vm.VMId)*" }
    if ($vmcxFilePath) {
        Write-Output "VMCX File Path: $vmcxFilePath"
    } else {
        Write-Output "VMCX file not found."
    }

    # Find and print the path of the VMRS file
    $vmrsFilePath = Find-Files -path $vmFilesPath -extension "vmrs" | Where-Object { $_ -like "*$($vm.VMId)*" }
    if ($vmrsFilePath) {
        Write-Output "VMRS File Path: $vmrsFilePath"
    } else {
        Write-Output "VMRS file not found."
    }

    # Print a line to separate the output for each VM
    Write-Output "----------------------------------------"
}

