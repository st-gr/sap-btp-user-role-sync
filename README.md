# SAP BTP User Synchronizer

This project synchronizes SAP BTP default users and roles with custom IdP users.

## Features
- Loads configuration from a YAML file.
- Retrieves OAuth tokens using client credentials (or from environment variables if not specified).
- Synchronizes users and their role assignments.
- Supports role copying between users (default user must exist).
- **New:** Bash implementation that mirrors the functionality of the Python version with detailed logging and configuration parsing.

## Implementations

### Python
Run the Python implementation using:
```bash
python sync_btp_users.py [--user <user_email>] [--copy-source <source_email> --copy-dest <dest_email>] [--config <config.yaml>]
```
### Bash
Run the Bash implementation using:
```bash
./sync_btp_users.sh [--user <user_email>] [--copy-source <source_email> --copy-dest <dest_email>] [--config <config.yaml>]
```
### PowerShell
Run the PowerShell 5.1 implemenation using:
```
sync_btp_users.ps1 [-user "<user_email>"] [-copy-source "<source_email>" -copy-dest "<dest_email>"] [-config "<config.yaml>"]
```
##Prerequisites
Create a service instance of the "Authorization and Trust Management Service" (xsuaa) with the "apiaccess" plan on your SAP BTP subaccount.
Create a service key from which you obtain the API URL, token, and credentials.
Required command-line tools for the Bash implementation: curl, jq.

For more details, see the source code and contributing guidelines.