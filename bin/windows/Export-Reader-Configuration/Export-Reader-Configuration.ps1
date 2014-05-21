# -----------------------------------------------------------------------------------------------------------------------------------------
# Script: Export-Reader-Configuration.ps1
# Author: Jonas Gröger <jonas.groeger@gmail.com>
# Date: 22.03.2014
# Keywords: Export, Reader, Configuration, Impinj, Speedreader
# Comments: This exports the configuration out of a Impinj Speedreader. You may have to change some settings according to your reader.
# -----------------------------------------------------------------------------------------------------------------------------------------

param (
    [Parameter(Mandatory=$true)] [string]$reader_ip,
    [int]$reader_port = 22,
    [string]$reader_username = "root",
    [string]$reader_password = "impinj",
    [string]$export_folder = "config"
)

# Create export folder (silent, overwrite existing)
New-Item -Force -ItemType directory -Path $export_folder | Out-Null

# A list of Tuples containing command objects to run. They contain Name, Command and the output directory
$commands = @(
    (New-Object PSObject -Property @{  Name = "ROSpec      ";  Command = "show rfid llrp rospec 0";      File = "rospec_0.xml"      }),
    (New-Object PSObject -Property @{  Name = "AccessSpec  ";  Command = "show rfid llrp accessspec 0";  File = "accessspec_0.xml"  }),
    (New-Object PSObject -Property @{  Name = "Capabilities";  Command = "show rfid llrp capabilities";  File = "capabilities.xml"  }),
    (New-Object PSObject -Property @{  Name = "Config      ";  Command = "show rfid llrp config";        File = "config.xml"        }),
    (New-Object PSObject -Property @{  Name = "Inbound     ";  Command = "show rfid llrp inbound";       File = "inbound.xml"       }),
    (New-Object PSObject -Property @{  Name = "Summary     ";  Command = "show rfid llrp summary";       File = "summary.xml"       })
)

# We want to collect the errors.
$errors = @()

# SSH the reader using the login credentials. Then we export all the configuration data and save them to files.
$commands | ForEach {
    Write-Host ("Exporting {0} {1, 10}" -f $_.Name, "") -NoNewLine

    # Connect and pipe to config file
    'C:\Program Files\PuTTY\plink.exe' -ssh -P $reader_port -l $reader_username -pw $reader_password $reader_ip $_.Command > $export_folder/$($_.File)

    # On error, save the name of the failed command and remove its empty configuration file
    if ($lastexitcode -eq 0) {
        Write-Host "Done!"
    } else {
        $errors += $($_.Name.Trim())
        Remove-Item $export_folder/$($_.File)
    }
}

# Done
if($errors.count -eq 0) {
    Write-Host ("Exported RFID-Reader configuration files to the '$export_folder' directory.")
} else {
    Write-Host ("Could not export the following configuration files: {0}" -f ($errors -join ", "))
}

Exit $errors.count

# TODO: Remove $export_folder in "if/else" above if ($errors.count -eq $commands.count), meaning everything went wrong, i.e. no connection is possible.
