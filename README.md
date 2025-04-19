# Meraki Wifi Manager

This repository contains the `Meraki Wifi Manager.ps1` script, a PowerShell tool designed to manage and automate tasks related to Cisco Meraki wireless networks.

## Features

- Retrieve and display Meraki network information.
- Add, update, or remove SSIDs.
- Configure wireless settings programmatically.
- Automate common administrative tasks for Meraki networks.

## Prerequisites

Before using the script, ensure the following:

1. **PowerShell**: The script requires PowerShell 5.1 or later.
2. **Meraki API Key**: Obtain an API key from the Meraki Dashboard. Refer to the [Meraki API Documentation](https://developer.cisco.com/meraki/api/) for details.

## Installation

1. Clone or download this repository.
2. Place the `Meraki Wifi Manager` folder in a directory of your choice.

## Usage

1. Double-click `Meraki Wifi Manager.cmd` or run the `Meraki Wifi Manager.ps1` in PowerShell.
2. On the menu choose R generate a Report CSV file.
3. Use that CSV file to plan updates to your SSIDs.
4. On the menu choose U to update your Meraki network SSIDS.

## Update

To use the CSV for Update purposes, change the AddRemoveSkip column to Add or Remove or Skip

- Remove: Only the SSIDName matters, other columns are ignored.  Meraki slot name is returned to default d SSID)
- Add   : Existing SSIDName will be updated if found, otherwise added to next available slot (number is ignored).
- Skip  : Ignore this row. Rows can also be deleted.