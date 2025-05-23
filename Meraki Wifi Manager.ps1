<#
Meraki Wifi Manager

This script reports or updates wifi settings across multiple Meraki networks

https://github.com/ITAutomator/MerakiWifiManager
https://www.itautomator.com
#>
######################
### Functions
######################
Function Get-Ssids ($apiKey="", $OrgId="", $NetworkId = "", $include_disabled_yesno = "no")
{
    # Usage: $Ssids, $sReturn = Get-Ssids $apikey $OrgId $NetworkId $include_disabled_yesno
    $sReturn = "OK"
    $ssids = $null
    $baseUrl = "https://api.meraki.com/api/v1"
    # Create the header for API calls
    $headers = @{
        "X-Cisco-Meraki-API-Key" = $apiKey
        "Content-Type"           = "application/json"
    }
    # Get all Ssids within the network
    $SsidsUrl = "$baseUrl/networks/$NetworkId/wireless/ssids"
    try {
        $Ssids = Invoke-RestMethod -Method Get -Uri $SsidsUrl -Headers $headers
    } catch {
        $warning = $_
        $bShowErr = $true
        if ($warning.ToString() -like "*endpoint only supports wireless networks*") {$bShowErr = $false}
        if ($bShowErr) {
            $sReturn = "ERR: Could not retrieve ssids for network: $($network.name) Error: $($warning)"
            return @(), $sReturn
        }
    }
    if ($include_disabled_yesno -ne "yes") {
        $ssids = $ssids | Where-Object Enabled -eq $true
    }
    if ($null -eq $ssids) {$ssids = @()}
    $sReturn = "OK: $($Ssids.Count) Ssids found"
    Return $Ssids, $sReturn
} # Get-Ssids
Function Get-Networks ($apiKey="", $OrgId="")
{
    # Usage: $networks, $sReturn = Get-Networks $apikey $OrgId
    $sReturn = "OK"
    $baseUrl = "https://api.meraki.com/api/v1"
    # Create the header for API calls
    $headers = @{
        "X-Cisco-Meraki-API-Key" = $apiKey
        "Content-Type"           = "application/json"
    }
    # Get all networks within the organization
    $networksUrl = "$baseUrl/organizations/$orgId/networks"
    try {
        $networks = Invoke-RestMethod -Method Get -Uri $networksUrl -Headers $headers
    } catch {
        $sReturn = "ERR: Failed to retrieve networks: $($_)"
        return $null, $sReturn
    }
    $sReturn = "OK: $($networks.Count) Networks found"
    Return $networks, $sReturn
} # Get-Networks
Function Get-OrgID ($apiKey="",$Organization="")
{
    # Usage: $OrgId, $sReturn = Get-OrgID $apikey $Organization
    $sReturn = "OK"
    $baseUrl = "https://api.meraki.com/api/v1"
    # Create the header for API calls
    $headers = @{
        "X-Cisco-Meraki-API-Key" = $apiKey
        "Content-Type"           = "application/json"
    }
    # Get all orgs for this API key
    $orgsUrl = "$baseUrl/organizations"
    try {
        $orgs = Invoke-RestMethod -Method Get -Uri $orgsUrl -Headers $headers
    } catch {
        $sReturn = "ERR: Failed to retrieve orgid: $($_)"
        return $null, $sReturn
    }
    # Find the Org
    $Org = $orgs | Where-Object Name -eq $Organization
    if (-Not $Org) {
        $sReturn = "ERR: Could not find Org $($Organization) among this APIKey's Orgs: $($orgs.name -join ", ")"
        return $null, $sReturn
    }
    Else {
        $OrgId = $Org.id
        $sReturn = "OK: $($Organization) can be reached at [$($Org.url)]"
    }
    Return $OrgId, $sReturn
} # Get-OrgID
Function APIkeyUpdate ($settings, $csvFile)
{
    # Usage: $settings = APIkeyUpdate $settings $csvFile $api_key_valuename
    Write-Host "Updating the settings file: $(Split-Path $csvFile -Leaf)"
    Write-Host "Meraki Organization name (from Organization > Configure > Settings)"
    $OrgName = PromptForString -Prompt "Organization (type 'exit' to cancel)" -defaultValue $settings.Organization
    if ($OrgName -eq 'exit') {
        Return "Err: Aborted"
    }
    Write-Host "Meraki API Key (from Account > My Profile > API key)"
    Write-Host "Note: The API key is stored encrypted in the settings file. Only this Windows account can read it."
    $apiKey_str = PromptForString -Prompt "API Key (type 'exit' to cancel)" -defaultValue "<API Key>"
    if ($apiKey_str -eq 'exit') {
        Return "Err: Aborted"
    }
    # Save settings
    $settings.Organization = $OrgName
    if ($apiKey_str -ne "<API Key>") { # only update if something was typed
        $settings.$api_key_valuename = EncryptString $apiKey_str # encrypt the API key (only this Windows account can read it)
    }
    $retVal = CSVSettingsSave $settings $csvFile
    Return "OK"
} # APIkeyUpdate
######################
## Main Procedure
######################
###
## To enable scrips, Run powershell 'as admin' then type
## Set-ExecutionPolicy Unrestricted
###
### Main function header - Put ITAutomator.psm1 in same folder as script
$scriptFullname = $PSCommandPath ; if (!($scriptFullname)) {$scriptFullname =$MyInvocation.InvocationName }
$scriptXML      = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+ ".xml"  ### replace .ps1 with .xml
$scriptDir      = Split-Path -Path $scriptFullname -Parent
$scriptName     = Split-Path -Path $scriptFullname -Leaf
$scriptBase     = $scriptName.Substring(0, $scriptName.LastIndexOf('.'))
$scriptVer      = "v"+(Get-Item $scriptFullname).LastWriteTime.ToString("yyyy-MM-dd")
$psm1="$($scriptDir)\ITAutomator.psm1";if ((Test-Path $psm1)) {Import-Module $psm1 -Force} else {write-output "Err 99: Couldn't find '$(Split-Path $psm1 -Leaf)'";Start-Sleep -Seconds 10;Exit(99)}
# Get-Command -module ITAutomator  ##Shows a list of available functions
#region Transcript Open
$Transcript = [System.IO.Path]::GetTempFileName()               
Start-Transcript -path $Transcript | Out-Null
#endregion Transcript Open
######################
Write-Host "-----------------------------------------------------------------------------"
Write-Host "$($scriptName) $($scriptVer)       User:$($env:computername)\$($env:username) PSver:$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
Write-Host ""
Write-Host "This script reports or updates wifi settings across multiple Meraki networks"
Write-Host ""
# Load settings
$csvFile = "$($scriptDir)\$($scriptBase) Settings.csv"
$settings = CSVSettingsLoad $csvFile
Write-Host "Settings file: $(split-path $csvFile -Leaf)"
# Defaults
$settings_updated = $false
$api_key_valuename = "apikey_secure_$($env:COMPUTERNAME)\$($env:USERNAME)"
if ($null -eq $settings.Organization) {$settings.Organization = "<Enter Org Name>"; $settings_updated = $true}
if ($null -eq $settings.$api_key_valuename)      {$settings.$api_key_valuename      = "<enter_api_key>"; $settings_updated = $true}
if ($settings_updated) {$retVal = CSVSettingsSave $settings $csvFile; Write-Host "Initialized - $($retVal)"}
try {
    $apiKey = Decryptstring $settings.$api_key_valuename
}
catch {
    $apikey = $null
}
if ($null -eq $apiKey) {
    $retVal = APIkeyUpdate $settings $csvFile
    Write-host $retVal
    if ($retVal -eq "OK") {
        Write-Host "Settings updated" -ForegroundColor Green
        $apiKey = Decryptstring $settings.$api_key_valuename
    }
}
Do { # action
    $UpdateChoice = ""
    $csv_update_file = (Get-ChildItem -Path $scriptDir -Filter "$($scriptBase)_Ssids_*.csv" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    Write-Host "--------------- Choices ------------------"
    Write-Host "[R] Report all Wifi settings to a new CSV file"
    Write-Host "[U] Update Wifi settings based on the most recent CSV file: " -NoNewline
    if ($null -eq $csv_update_file) {
        Write-Host "No CSV file found" -ForegroundColor Yellow
    } else {
        Write-Host (Split-Path $csv_update_file -Leaf) -ForegroundColor Green
    }
    Write-Host "[A] Apikey and Organization name. api_key: " -NoNewline
    try {Write-host "$($apiKey.Substring(0,5))*****" -ForegroundColor Green -NoNewline} Catch {Write-host "Not set" -ForegroundColor Yellow -NoNewline}
    Write-Host " Org: " -NoNewline
    Write-host $settings.Organization -ForegroundColor Green
    Write-Host "[X] Exit"
    Write-Host "-------------------------------------------------------"
    $choice = PromptForString "Choice [blank to exit]"
    if (($choice -eq "") -or ($choice -eq "X")) {
        Break
    } # Exit
    if ($choice -eq "A")
    { # apikey update
        $retVal = APIkeyUpdate $settings $csvFile
        if ($retVal -eq "OK") {
            Write-Host "Settings updated" -ForegroundColor Green
            $apiKey = Decryptstring $settings.$api_key_valuename
        }
        else {
            Write-Host "Settings not updated" -ForegroundColor Yellow
        }
    } # apikey update
    if ($choice -eq "R")
    { # report
        $include_disabled_yesno = AskForChoice "Include disabled SSIDs (all 15 slots will be listed)" -Choices @("&Yes","&No") -DefaultChoice 1 -ReturnString
        # Orgid
        $OrgId, $sReturn = Get-OrgID $apiKey $settings.Organization
        Write-Host $sReturn
        if ($sReturn.StartsWith("ERR")) {PressEnterToContinue;Continue}
        # Networks
        $networks, $sReturn = Get-Networks $apiKey $OrgId
        Write-Host $sReturn
        if ($sReturn.StartsWith("ERR")) {PressEnterToContinue;Continue}
        # ssids
        $datesnap = get-date -format d
        $date = get-date -format "yyyy-MM-dd_HH-mm-ss"
        $objSSids = @()
        # Loop through each network 
        $i_count = $networks.Count
        $i = 0
        foreach ($network in $networks) {
            $i += 1
            $NetworkId = $network.id
            $NetworkName = $network.name
            Write-Host " Network $($i) of $($i_count): $($NetworkName) (ID: $($NetworkId))" -NoNewline
            # ssids (wifis)
            $Ssids, $sReturn = Get-Ssids $apikey $OrgId $NetworkId $include_disabled_yesno
            Write-Host "    $($sReturn)"
            if ($sReturn.StartsWith("ERR")) {PressEnterToContinue;Continue}
            foreach ($ssid in $ssids)
            { # ssids
                $objSSids += [pscustomobject]@{
                    DateSnap = $datesnap
                    Organization  = $settings.Organization
                    NetworkName   = $network.name
                    AddRemoveSkip     = "Skip"
                    SSIDName            = $ssid.name
                    SSIDPassword        = $ssid.psk
                    Number              = $ssid.number
                    defaultVlanId       = $ssid.defaultVlanId
                    useVlanTagging      = $ssid.useVlanTagging
                    authMode            = $ssid.authMode
                    encryptionMode      = $ssid.encryptionMode
                    wpaencryptionMode   = $ssid.wpaencryptionMode
                    ipAssignmentMode    = $ssid.ipAssignmentMode
                    lanIsolationEnabled = $ssid.lanIsolationEnabled
                    visible             = $ssid.visible
                    Enabled             = $ssid.Enabled
                } # object
            } # ssids
        } # networks
        #
        $scriptCSV      = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+ "_Ssids_"+$date+".csv"
        $objSSids | Sort-Object Organization,NetworkName,Name | export-csv -path $scriptCSV -encoding utf8 -notypeinformation
        Write-Host "Exported to: $(split-path $scriptCSV -leaf)"
        Write-Host ""
        Write-Host "To use the CSV for Update purposes, change the AddRemoveSkip column to Add or Remove or Skip"
        Write-Host "- Remove: Only the SSIDName matters, other columns are ignored.  Meraki slot name is returned to default (Unconfigured SSID)"
        Write-Host "- Add   : Existing SSIDName will be updated if found, otherwise added to next available slot (number is ignored)."
        Write-Host "- Skip  : Ignore this row. Rows can also be deleted."
        Write-Host ""
        If (askForChoice "Open CSV for editing now?") {
            Start-Process $scriptCSV
        }
    } # report
    if ($choice -in "U")
    { # update
        if ($null -eq $csv_update_file) {
            Write-Host "No CSV file found" -ForegroundColor Yellow
            PressEnterToContinue
            Continue
        }
        $file_name = PromptForString -Prompt "Type a file name or press enter (type 'exit' to cancel)" -defaultValue (Split-Path $csv_update_file -Leaf)
        if ($file_name -eq 'exit') {
            Continue
        }
        $csv_update_file = "$($scriptDir)\$($file_name)"
        Write-Host "  File : " -NoNewline
        write-host (Split-Path $csv_update_file -Leaf) -ForegroundColor Green
        $csvData = Import-Csv -Path $csv_update_file
        Write-Host "   Add : " -NoNewline
        Write-Host ($csvData | Where-Object AddRemoveSkip -eq "Add").count -ForegroundColor Green
        Write-Host "Remove : " -NoNewline
        Write-Host ($csvData | Where-Object AddRemoveSkip -eq "Remove").count -ForegroundColor Green
        Write-Host "  Skip : " -NoNewline
        Write-Host ($csvData | Where-Object AddRemoveSkip -eq "Skip").count -ForegroundColor Green
        Write-Host "------------------------"
        Write-Host " Total : " -NoNewline
        Write-Host $csvData.count -ForegroundColor Green
        $total_updates = ($csvData | Where-Object AddRemoveSkip -eq "Add").count + ($csvData | Where-Object AddRemoveSkip -eq "Remove").count 
        PressEnterToContinue "Press Enter to process $($total_updates) updates"
        # Network info
        $baseUrl = "https://api.meraki.com/api/v1"
        # Create the header for API calls
        $headers = @{
            "X-Cisco-Meraki-API-Key" = $apiKey
            "Content-Type"           = "application/json"
        }
        # Orgid
        $OrgId, $sReturn = Get-OrgID $apiKey $settings.Organization
        Write-Host $sReturn
        if ($sReturn.StartsWith("ERR")) {PressEnterToContinue;Continue}
        # Networks
        $Ssids_networkid = ""
        $networks, $sReturn = Get-Networks $apiKey $OrgId
        Write-Host $sReturn
        if ($sReturn.StartsWith("ERR")) {PressEnterToContinue;Continue}
        # Network info
        $actions = @("Remove","Add")
        foreach ($action in $actions)
        { # action
            $csvChanges = $csvData | Where-Object AddRemoveSkip -eq $action
            $i = 0
            ForEach ($csvChange in $csvChanges)
            { # csvChange
                $i += 1
                Write-Host "$($action) $($i) [$($csvChange.NetworkName)] " -NoNewline
                Write-host  $csvChange.SSIDName -ForegroundColor Yellow -NoNewline
                $Network = $networks | Where-Object name -eq $csvChange.NetworkName | Select-Object -first 1
                if ($null -eq $Network) { Write-Host "ERR: Couldn't find network $($csvChange.NetworkName)";PressEnterToContinue;exit}
                $NetworkId = $Network.id
                $NetworkUrl = $Network.url
                if ($Ssids_networkid -ne $NetworkId)
                { # get ssids for this network
                    $Ssids, $sReturn = Get-Ssids $apikey $OrgId $NetworkId "yes"
                    $Ssids_networkid = $NetworkId
                } # get ssids for this network
                # Check if SSID exists (by name)
                $ssid = $Ssids | Where-Object { $_.name -eq $csvChange.SSIDName } | Select-Object -First 1
                # No SSID found matching name
                if ($null -eq $ssid) {
                    if ($action -eq "Add")
                    { # Add
                        # Choose first unconfigured SSID slot (that is also disabled)
                        $ssid = $Ssids | Where-Object { ($_.name -like "Unconfigured SSID*") -and ($_.enabled -eq $false) } | Select-Object -First 1
                        if ($null -eq $ssid)  {
                            Write-Host "ERR: No free slots for a new SSID" -ForegroundColor Yellow
                            PressEnterToContinue
                        } # doesn't exist
                    } # Add
                    else
                    { # Remove
                        Write-Host " OK: Already removed" -ForegroundColor Green
                    } # Remove
                }
                if ($ssid)
                { # ssid to update
                    Write-Host " Slot [$(1+$ssid.number)]" -NoNewline
                    if ($action -eq "add")
                    { # add
                        # targets for action: add
                        # basics
                        $target_name           = $csvChange.SSIDName
                        $target_enabled        = $csvChange.Enabled -ne 'false' # default is true unless explicit
                        $target_visible        = $csvChange.visible -ne 'false' # default is true unless explicit
                        # auth
                        $target_psk            = $csvChange.SSIDPassword
                        $target_authMode       = $csvChange.authMode
                        $target_encryptionMode = $csvChange.encryptionMode
                        # networking
                        $target_ipAssignmentMode    = if ($csvChange.ipAssignmentMode -eq '') {"Bridge mode"} else {$csvChange.ipAssignmentMode}
                        $target_lanIsolationEnabled = $csvChange.lanIsolationEnabled -eq 'true' # default is false unless explicit
                        $target_useVlanTagging = $csvChange.useVlanTagging -eq 'true' # default is false unless explicit
                        $target_defaultVlanId  = [int]$csvChange.defaultVlanId  # blank / null is 0
                    } # add
                    else
                    { # remove
                        # targets for action: remove
                        # basics
                        $target_name           = "Unconfigured SSID $(1+$ssid.number)"
                        $target_enabled        = $false
                        $target_visible        = $true
                        # auth
                        $target_psk            = $null
                        $target_authMode       = "open"
                        $target_encryptionMode = "open"
                        # networking
                        $target_ipAssignmentMode    = "NAT mode"
                        $target_lanIsolationEnabled = $false
                        $target_useVlanTagging = $false
                        $target_defaultVlanId  = 0
                    } # remove
                    # ipAssignmentMode
                    # Bridge mode: Normal network access
                    # Layer 3 roaming: Same as Bridge mode with a virtualization layer. Generally not advised since L2 roaming works, and L3 roaming creates an extra tunnel back to the orginal VLan (https://www.reddit.com/r/networking/comments/13dkpbt/meraki_l3_roaming_is_it_necessary/)
                    # NAT mode: (useVlanTagging,defaultVlanId must be null) clients are isolated from other wifi clients on a Meraki assigned network
                    if ($target_ipAssignmentMode -eq "NAT mode")
                    { # NAT mode
                        $target_useVlanTagging = $false # default is false unless explicit
                        $target_defaultVlanId  = 0 # 0 is same as null
                    } # NAT mode
                    if ($target_ipAssignmentMode -ne "Bridge mode") {
                        $target_lanIsolationEnabled = $false # lanIsolationEnabled is not supported in NAT mode or Layer 3 roaming mode
                    } # not Bridge mode
                    # Other adjustments
                    # see which update is needed
                    $sWarnings = @()
                    $payload= @{}
                    ## basics: name enabled visible lanIsolationEnabled
                    if ($ssid.name -ne $target_name)                               {$sWarnings += "   name:                Change [$($ssid.name)] to [$($target_name)]"                              ; $payload['name'] = $target_name}
                    if ($ssid.enabled -ne $target_enabled)                         {$sWarnings += "   enabled:             Change [$($ssid.enabled)] to [$($target_enabled)]"                        ; $payload['enabled'] = $target_enabled}
                    if ($ssid.visible -ne $target_visible)                         {$sWarnings += "   visible:             Change [$($ssid.visible)] to [$($target_visible)]"                        ; $payload['visible'] = $target_visible}
                    ## auth: psk authMode encryptionMode wpaencryptionMode
                    if (($ssid.psk -ne $target_psk) -and ($target_encryptionMode -ne "open")) {$sWarnings += "   psk:                 Change [$($ssid.psk)] to [$($target_psk)]"                                ; $payload['psk'] = $target_psk}
                    if ($ssid.authMode -ne $target_authMode)                       {$sWarnings += "   authMode:            Change [$($ssid.authMode)] to [$($target_authMode)]"                      ; $payload['authMode'] = $target_authMode}
                    if ($ssid.encryptionMode -ne $target_encryptionMode)           {$sWarnings += "   encryptionMode:      Change [$($ssid.encryptionMode)] to [$($target_encryptionMode)]"          ; $payload['encryptionMode'] = $target_encryptionMode}
                    ## networking: ipAssignmentMode useVlanTagging defaultVlanId
                    if ($ssid.ipAssignmentMode -ne $target_ipAssignmentMode)       {$sWarnings += "   ipAssignmentMode:    Change [$($ssid.ipAssignmentMode)] to [$($target_ipAssignmentMode)]"      ; $payload['ipAssignmentMode'] = $target_ipAssignmentMode}
                    $ssid_defaultVlanId = [int]$ssid.defaultVlanId # null/blank is 0
                    if ($ssid_defaultVlanId -ne $target_defaultVlanId)             {$sWarnings += "   defaultVlanId:       Change [$($ssid.defaultVlanId)] to [$($target_defaultVlanId)]"            ; $payload['defaultVlanId'] = $target_defaultVlanId}
                    $ssid_useVlanTagging = if($null -eq $ssid.useVlanTagging) {$false} else {$ssid.useVlanTagging -eq 'true'} # default is false unless explicitly null
                    if ($ssid_useVlanTagging -ne $target_useVlanTagging)           {$sWarnings += "   useVlanTagging:      Change [$($ssid.useVlanTagging)] to [$($target_useVlanTagging)]"          ; $payload['useVlanTagging'] = $target_useVlanTagging}
                    $ssid_lanIsolationEnabled = if($null -eq $ssid.lanIsolationEnabled) {$false} else {$ssid.lanIsolationEnabled -eq 'true'} # default is false unless explicitly null
                    if ($ssid_lanIsolationEnabled -ne $target_lanIsolationEnabled) {$sWarnings += "   lanIsolationEnabled: Change [$($ssid.lanIsolationEnabled)] to [$($target_lanIsolationEnabled)]"; $payload['lanIsolationEnabled'] = $target_lanIsolationEnabled}
                    ##
                    if ($sWarnings.count -eq 0)
                    { # no update needed
                        Write-Host " OK: Already set properly" -ForegroundColor Green
                    } # no update needed
                    else
                    { # update needed
                        Write-Host ""
                        $sWarnings | Out-Host
                        $uri = "$baseUrl/networks/$NetworkId/wireless/ssids/$($ssid.number)"
                        if ($UpdateChoice -ne "Update All") {
                            $UpdateChoice = askForChoice $msg -Choices @("&Update","Update &All","&Skip","E&xit") -DefaultChoice 1 -ReturnString
                            if ($UpdateChoice -eq "Exit") {
                                Exit
                            }
                        } # update choice
                        if ($UpdateChoice -eq "Skip") {
                            Write-Host "    Skipping"  -ForegroundColor Yellow
                        } # skip
                        else { # not skip
                            try {
                                $results = Invoke-RestMethod -Uri $uri -Headers $headers -Method Put -Body ($payload | ConvertTo-Json -Depth 5)
                            } catch {
                                $warning = $_
                                Write-Host "ERR: $($warning.ToString())" -ForegroundColor Yellow
                                PressEnterToContinue
                            }
                            Write-Host "    OK: Updated in network [$($NetworkUrl)] $($results.wpaEncryptionMode)"  -ForegroundColor Yellow
                            $ssids_networkid = "RESET" # force ssids to be reloaded
                        } # not skip
                    } # update needed
                } # ssid to update
            } # csvChange
        } # action
    } # update
    Write-Host "Done"
    Start-sleep 2
} While ($true) # loop until Break 
#region Transcript Save
Stop-Transcript | Out-Null
$TranscriptTarget = "$($scriptDir)\Logs\$($scriptBase)_$(Get-Date -format "yyyy-MM-dd HH-mm-ss")_transcript.txt"
New-Item -Path (Split-path $TranscriptTarget -Parent) -ItemType Directory -Force | Out-Null
If (Test-Path $TranscriptTarget) {Remove-Item $TranscriptTarget -Force}
Move-Item $Transcript $TranscriptTarget -Force
Write-Host "Exited. Transcript saved to: $(Split-path $TranscriptTarget -Leaf)"
#endregion Transcript Save