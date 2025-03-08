"""
.SYNOPSIS
    Synchronizes SAP BTP default users and roles with custom IdP users.

.DESCRIPTION
    This script loads configuration from a YAML file (config.yaml), obtains an OAuth token using client credentials,
    and then synchronizes users and roles between the “sap.default” and “sap.custom” origins.
    Optionally you can synchronize a single user (with --user) or copy role assignments from one user to another 
    (with --copy-source and --copy-dest).
    If the client credentials (clientid and clientsecret) are not present in the YAML configuration file, the script 
    attempts to retrieve them from the environment variables SAP_BTP_CLIENTID and SAP_BTP_CLIENTSECRET respectively.

.PREREQUISITES
    You need to create a service instance of the service 'Authorization and Trust Management Service'
    xsuaa, plan apiaccess on the BTP subaccount first
    then create a service key from which you get the token, apiurl, and credentials.

.PARAMETER user
    Email address of a user to synchronize exclusively.

.PARAMETER copy_source
    Email of the default user to copy roles from.

.PARAMETER copy_dest
    Email of the destination user to copy roles to.

.USAGE
    py sync_btp_users.py [--user <user_email>] [--copy-source <source_email> --copy-dest <dest_email>]

.NOTES
    - This script uses only built-in PowerShell cmdlets (using Invoke-RestMethod for REST calls).
    - A very simple YAML importer is defined here so that no extra modules are needed. 
      (It supports a limited YAML syntax expected in the configuration file.)
    - This script is licensed under the MIT License.
"""
import yaml
import requests
import logging
import argparse
import os
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Config:
    apiurl: str
    access_token_url: str
    clientid: str
    clientsecret: str
    subaccountid: str
    skip_users: list = field(default_factory=list)

class UserSynchronizer:
    def __init__(self, config: Config):
        self.config = config
        self.access_token = None
        self.default_users = {}
        self.custom_users = {}
        self.role_collections = {}
        self.get_oauth_token()  # Moved token retrieval to constructor

    def load_config(config_file: str) -> Config:
        """Load configuration from YAML file and retrieve missing client credentials from env variables"""
        try:
            with open(config_file, 'r') as file:
                config_data = yaml.safe_load(file)
                # Retrieve client credentials from environment variables if not present in YAML
                config_data['clientid'] = config_data.get('clientid') or os.environ.get('SAP_BTP_CLIENTID')
                config_data['clientsecret'] = config_data.get('clientsecret') or os.environ.get('SAP_BTP_CLIENTSECRET')
                return Config(**config_data)
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            raise

    def get_oauth_token(self) -> None:
        """Obtain OAuth2 token using client credentials"""
        try:
            response = requests.post(
                self.config.access_token_url,
                auth=(self.config.clientid, self.config.clientsecret),
                data={'grant_type': 'client_credentials'}
            )
            response.raise_for_status()
            self.access_token = response.json()['access_token']
            logger.info("Successfully obtained OAuth token")
        except Exception as e:
            logger.error(f"Failed to obtain OAuth token: {str(e)}")
            raise

    def get_headers(self) -> Dict:
        """Return headers with OAuth token"""
        return {
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/json'
        }

    def get_users(self, origin: str) -> Dict:
        """Retrieve users from specified origin"""
        try:
            response = requests.get(
                f"{self.config.apiurl}/Users",
                headers=self.get_headers(),
                params={'filter': f'origin eq "{origin}"'}
            )
            response.raise_for_status()
            users = {
                user['emails'][0]['value'].strip().lower(): user  # harmonize email to lower-case
                for user in response.json()['resources']
            }
            logger.info(f"Retrieved {len(users)} users from {origin}")
            return users
        except Exception as e:
            logger.error(f"Failed to retrieve users from {origin}: {str(e)}")
            raise

    def create_custom_user(self, default_user: Dict) -> None:
        """Create a new user in sap.custom based on sap.default user"""
        try:
            user_data = {
                'userName': default_user['userName'],
                'emails': [{'value': default_user['emails'][0]['value'], 'primary': False}],
                'origin': 'sap.custom',
                'zoneId': self.config.subaccountid,
                'schemas': ['urn:scim:schemas:core:1.0']
            }
            
            response = requests.post(
                f"{self.config.apiurl}/Users",
                headers=self.get_headers() | {'Content-Type': 'application/json'},
                json=user_data
            )
            response.raise_for_status()
            logger.info(f"Created custom user: {default_user['userName']}")
        except Exception as e:
            logger.error(f"Failed to create custom user {default_user['userName']}: {str(e)}")
            raise

    def get_role_collections(self) -> None:
        """Retrieve all role collections"""
        try:
            response = requests.get(
                f"{self.config.apiurl}/Groups",
                headers=self.get_headers()
            )
            response.raise_for_status()
            self.role_collections = {
                role['id']: role 
                for role in response.json()['resources']
            }
            logger.info(f"Retrieved {len(self.role_collections)} role collections")
        except Exception as e:
            logger.error(f"Failed to retrieve role collections: {str(e)}")
            raise

    def assign_role_to_user(self, role_id: str, user_id: str, user_email: str) -> None:
        """Assign a role to a custom user"""
        try:
            member_data = {
                'origin': 'sap.custom',
                'type': 'USER',
                'value': user_id
            }
            
            response = requests.post(
                f"{self.config.apiurl}/Groups/{role_id}/members",
                headers=self.get_headers() | {'Content-Type': 'application/json'},
                json=member_data
            )
            response.raise_for_status()
            logger.info(f"Assigned role {role_id} to user {user_email} ({user_id})")
        except Exception as e:
            logger.error(f"Failed to assign role {role_id} to user {user_email} ({user_id}): {str(e)}")

    def remove_role_from_user(self, role_id: str, user_id: str, user_email: str) -> None:
        """Remove a role from a custom user"""
        try:
            response = requests.delete(
                f"{self.config.apiurl}/Groups/{role_id}/members/{user_id}",
                headers=self.get_headers()
            )
            response.raise_for_status()
            logger.info(f"Removed role {role_id} from user {user_email} ({user_id})")
        except Exception as e:
            logger.error(f"Failed to remove role {role_id} from user {user_email} ({user_id}): {str(e)}")
    
    def sync_users_and_roles(self, target_email: str = None) -> None:
        """Main synchronization process"""
        # Removed separate token retrieval here since token is obtained in __init__

        # Lower-case target_email if provided
        if target_email:
            target_email = target_email.strip().lower()

        # Lower-case skip_users
        skip = {u.strip().lower() for u in self.config.skip_users}

        # Get users from both origins
        self.default_users = self.get_users('sap.default')
        self.custom_users = self.get_users('sap.custom')

        # Skip users configured in the YAML file
        if target_email:
            if target_email in skip:
                logger.info(f"Skipping synchronization for target user: {target_email}")
                return
            self.default_users = (self.default_users.get(target_email) and {target_email: self.default_users[target_email]}) or {}
            self.custom_users = (self.custom_users.get(target_email) and {target_email: self.custom_users[target_email]}) or {}
        else:
            self.default_users = {email: user for email, user in self.default_users.items() if email not in skip}
            self.custom_users = {email: user for email, user in self.custom_users.items() if email not in skip}

        # Create missing custom users
        for email, default_user in self.default_users.items():
            if email not in self.custom_users:
                self.create_custom_user(default_user)

        # Refresh custom users list
        self.custom_users = self.get_users('sap.custom')
        if target_email:
            self.custom_users = self.custom_users.get(target_email) and {target_email: self.custom_users[target_email]} or {}
        else:
            self.custom_users = {email: user for email, user in self.custom_users.items() if email not in skip}

        # Get role collections
        self.get_role_collections()

        # Sync roles: assign missing roles
        for email, default_user in self.default_users.items():
            if email in self.custom_users:
                custom_user = self.custom_users[email]
                default_roles = {g['value'] for g in default_user.get('groups', [])}
                custom_roles = {g['value'] for g in custom_user.get('groups', [])}
                # Assign missing roles
                for role_id in default_roles - custom_roles:
                    if role_id in self.role_collections:
                        self.assign_role_to_user(role_id, custom_user['id'], email)
                # Remove extra roles not present in default user groups
                for role_id in custom_roles - default_roles:
                    if role_id in self.role_collections:
                        self.remove_role_from_user(role_id, custom_user['id'], email)

    def copy_role_assignments(self, source_email: str, dest_email: str) -> None:
        """Copy role assignments from source default user to destination default and custom users"""
        source_email = source_email.strip().lower()
        dest_email = dest_email.strip().lower()
        
        # Retrieve all default and custom users (token is already available)
        default_users_all = self.get_users('sap.default')
        custom_users_all = self.get_users('sap.custom')
        
        if source_email not in default_users_all:
            logger.error(f"Source default user {source_email} not found")
            return
        if dest_email not in default_users_all:
            logger.error(f"Destination default user {dest_email} not found")
            return

        source_default = default_users_all[source_email]
        dest_default = default_users_all[dest_email]
        
        # Update destination default user roles:
        source_roles_default = {g['value'] for g in source_default.get('groups', [])}
        dest_roles_default = {g['value'] for g in dest_default.get('groups', [])}
        self.get_role_collections()
        for role_id in source_roles_default - dest_roles_default:
            if role_id in self.role_collections:
                self.assign_role_to_user(role_id, dest_default['id'], dest_email)
        for role_id in dest_roles_default - source_roles_default:
            if role_id in self.role_collections:
                self.remove_role_from_user(role_id, dest_default['id'], dest_email)
        
        # Ensure destination custom user exists
        if dest_email not in custom_users_all:
            self.create_custom_user(dest_default)
            custom_users_all = self.get_users('sap.custom')
        if dest_email not in custom_users_all:
            logger.error(f"Destination custom user {dest_email} not found even after creation")
            return
        dest_custom = custom_users_all[dest_email]
        
        # Update destination custom user roles:
        source_roles_custom = {g['value'] for g in source_default.get('groups', [])}
        dest_roles_custom = {g['value'] for g in dest_custom.get('groups', [])}
        for role_id in source_roles_custom - dest_roles_custom:
            if role_id in self.role_collections:
                self.assign_role_to_user(role_id, dest_custom['id'], dest_email)
        for role_id in dest_roles_custom - source_roles_custom:
            if role_id in self.role_collections:
                self.remove_role_from_user(role_id, dest_custom['id'], dest_email)

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--user', type=str, help="Email of the user to synchronize exclusively")
        parser.add_argument('--copy-source', type=str, help="Email of the default user to copy roles from")
        parser.add_argument('--copy-dest', type=str, help="Email of the destination user to copy roles to")
        args = parser.parse_args()
        
        # Load configuration
        config = UserSynchronizer.load_config('config.yaml')
        synchronizer = UserSynchronizer(config)
        
        # If copy flags provided, perform role copy and exit
        if args.copy_source and args.copy_dest:
            synchronizer.copy_role_assignments(args.copy_source, args.copy_dest)
        else:
            synchronizer.sync_users_and_roles(args.user)
        
        logger.info("Synchronization completed successfully")
    except Exception as e:
        logger.error(f"Synchronization failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()