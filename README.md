# Meraki Wifi Manager

This repository contains the `Meraki Wifi Manager.ps1` script, a PowerShell tool designed to manage and automate tasks related to Cisco Meraki wireless networks.

<img src=https://raw.githubusercontent.com/ITAutomator/Assets/main/Meraki/MerakiWifiMain.png alt="screenshot" width="500"/>

User guide: Click [here](https://github.com/ITAutomator/MerakiWifiManager)  
Download from GitHub as [ZIP](https://github.com/ITAutomator/MerakiWifiManager/archive/refs/heads/main.zip)  
Or Go to GitHub [here](https://github.com/ITAutomator/MerakiWifiManager) and click `Code` (the green button) `> Download Zip`  

## Features

- Retrieve a CSV report of all Meraki SSIs in the organization.
- Add, update, or remove SSIDs in batch mode using CSV as input.

## Prerequisites

Before using the script, ensure the following:

1. **Organization name**: Obtain your Organization name (*Organization > Configure > Settings*). [Meraki Org Name Docs](https://documentation.meraki.com/General_Administration/Organizations_and_Networks/Organization_Menu/Organization_Settings)
2. **Meraki API Key**: Obtain an API key from the Meraki Dashboard (*Account > My Profile > API key*). Refer to the [Meraki API Docs](https://developer.cisco.com/meraki/api-v1/authorization/#obtaining-your-meraki-api-key/) for details.

## Installation

1. Clone or download this repository.
2. Place the `Meraki Wifi Manager` folder in a directory of your choice.

## Usage

1. Double-click `Meraki Wifi Manager.cmd` or run the `Meraki Wifi Manager.ps1` in PowerShell.
2. On the menu choose R generate a Report CSV file.
3. Use that CSV file to plan updates to your SSIDs.
4. On the menu choose U to update your Meraki network SSIDS.

Notes:  
The script is careful about making changes, so that it can be run repeatedly, skipping items that are already OK.  
If no changes to a SSID are required, the change is displayed as already OK and processing continues without interaction.  
If properties are changing, each property change is displayed and confirmed before any change is made.  

## Menu: Report

Use the Report menu to export a CSV file with all the SSID settings for the organization.  
This CSV can be used as the basis for an Update operation.  

Initially, all rows are set to `Skip`.  
Change rows to `Add` or `Remove` as needed.  

- If you are just updating an existing SSID row, use `Add`.  
- If you want to add more rows, add them manually by copying existing SSIDs and changing their contents.  

## Menu: Update

To use the CSV for Update purposes, change the AddRemoveSkip column to Add or Remove or Skip

- Remove: Only the SSIDName matters, other columns are ignored.  Meraki slot name is returned to the default "Unconfigured SSID" name.  
  Removes are processed first.  This ensures that free slots are available for Adds.  
- Add   : Existing SSIDName will be updated if found, otherwise added to next available slot (slot number is ignored).
- Skip  : Ignore this row. Rows can also be deleted.  

<img src=https://raw.githubusercontent.com/ITAutomator/Assets/main/Meraki/MerakiWifiUpdate.png alt="screenshot" width="500"/>

## CSV File Fields

| **Field Name**       | **Description**                                                                 |
|----------------------|---------------------------------------------------------------------------------|
|                      | KEY FIELDS                      |
| `SSIDName`           | The name of the SSID to be added, updated, or removed.                         |
| `AddRemoveSkip`      | Specifies the action for the SSID: `Add`, `Remove`, or `Skip`.   |
|                      | `Add` If SSID exists, it is updated instead of added.    |
|                      | `Remove` If SSID exists, it is disabled and given a standard name `Unconfigured SSID`  |
|                      | `Skip`.  This row is ignored and not processed.    |
|                      | BASICS                      |
| `SlotNumber`         | (Read-only) The slot number for the SSID is ignored. Add/Remove actions are always keyed off of SSIDName.|
| `enabled`            | `True` (default) or `False` if the SSID is disabled                   |
| `visible`            | `True` (default) or `False` if the SSID signal is not advertised (but still usable)                   |
|                      | AUTHENTICATION                    |
| `authMode`           | `open` (no password) or `psk` (pre shared key - requires a password)                           |
| `SSIDPassword`       | The password for the SSID, if applicable.                                      |
| `encryptionMode`     | (Read-only) The type of encryption used. e.g. `WPA2 only` (default)                     |
|                      |   NETWORKING                    |
| `ipAssignmentMode`   | The method used to assign IPs `NAT mode` `Bridge mode` or `Layer 3 roaming`        |
|                      | `NAT mode` Meraki assigns IPs in an isolated 10.0.0.0/8 network. (Sets useVlanTagging to False)     |
|                      | `Bridge mode` (default) Clients are bridged to the existing network/VLAN and get DHCP from there     |
|                      | `Layer 3 roaming` same as Bridge mode, but with an L3 virtual tunnel back to the original AP (use if L2 roaming doesn't work)   |
| `useVlanTagging`     | `True` (requires defaultVlanId) or `False` (default)                          |
| `defaultVlanId`      | The VLAN ID associated with the SSID (ignored if useVlanTagging is False).           |
| `lanIsolationEnabled`| `True` (requires Bridge mode) or `False` (default). Isolates clients from other clients (wired and wireless)                        |

More info here: [www.itautomator.com](https://www.itautomator.com/meraki-wifi-manager/)