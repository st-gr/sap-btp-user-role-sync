# SAP BTP User Synchronizer

This project synchronizes SAP BTP default users and roles with custom IdP users.

## Features
- Loads configuration from a YAML file.
- Retrieves OAuth tokens using client credentials (or from environment variables if not specified).
- Synchronizes users and their role assignments.
- Supports role copying between users (default user must exist).
- Bash implementation that mirrors the functionality of the Python version with detailed logging and configuration parsing.

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
sync_btp_users.ps1 [-user "<user_email>"] [-copy_source "<source_email>" -copy_dest "<dest_email>"] [-config "<config.yaml>"]
```

## Usage

When run without any parameters, the scripts synchronize all users from `sap.default` to `sap.custom`, creating missing custom users and syncing their role assignments.

### Parameters

| Parameter | Description |
|-----------|-------------|
| `--config` | Path to the configuration file. Defaults to `config.yaml` in the current working directory. |
| `--user` | Synchronize only a single user by email address. |
| `--copy-source` / `--copy-dest` | Copy role assignments from a source user to a destination user. Both parameters must be provided together. |

### Copy Role Assignments

The copy functionality (`--copy-source` and `--copy-dest`) copies role assignments from a source default user to a destination user:
- Updates roles for both the destination's default and custom user
- Both source and destination default users must exist
- Creates the destination custom user if it doesn't exist

## Prerequisites

- Create a service instance of the "Authorization and Trust Management Service" (xsuaa) with the "apiaccess" plan on your SAP BTP subaccount.
- Create a service key from which you obtain the API URL, token, and credentials.
- Required command-line tools for the Bash implementation: curl, jq.

## Configuration

See `template-config.yaml` for the configuration template. You can define user emails to be skipped from synchronization using the `skip_users` list.

For more details, see the source code and contributing guidelines.