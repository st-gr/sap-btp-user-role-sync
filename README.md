# SAP BTP User Synchronizer

This project synchronizes SAP BTP default users and roles with custom IdP users.

## Features
- Loads configuration from a YAML file.
- Retrieves OAuth tokens using client credentials (or from environment variables if not specified).
- Synchronizes users and their role assignments.
- Supports role copying between users (default user must exist).

## Usage

Run the Python implementation using:
```
python sync_btp_users.py [--user <user_email>] [--copy-source <source_email> --copy-dest <dest_email>]
```
Run the PowerShell 5.1 implemenation using:
```
sync_btp_users.ps1 [-user "<user_email>"] [-copy-source "<source_email>" -copy-dest "<dest_email>"]
```

For more details, see the source code and contributing guidelines.