#!/usr/bin/env bash
#
# .SYNOPSIS
#    Synchronizes SAP BTP default users and roles with custom IdP users.
#
# .DESCRIPTION
#    This script loads configuration from a YAML file (default: config.yaml), obtains an OAuth token using client credentials,
#    and then synchronizes users and roles between the 'sap.default' and 'sap.custom' origins.
#    Optionally, you can synchronize a single user (using --user) or copy role assignments from one user to another
#    (using --copy-source and --copy-dest).
#    If the client credentials (clientid and clientsecret) are not provided in the YAML configuration file, the script will
#    attempt to retrieve them from the environment variables SAP_BTP_CLIENTID and SAP_BTP_CLIENTSECRET.
#
# .PREREQUISITES
#    - Create a service instance of the "Authorization and Trust Management Service" (xsuaa) with the "apiaccess" plan on your SAP BTP subaccount.
#    - Create a service key from which you obtain the API URL, token, and credentials.
#    - Required command-line tools: curl, jq.
#
# .PARAMETERS
#    --config       Path to the configuration file (default: config.yaml).
#    --user         Email address of a user to synchronize exclusively.
#    --copy-source  Email address of the default user to copy roles from.
#    --copy-dest    Email address of the destination user to copy roles to.
#
# .USAGE
#    ./sync_btp_users.sh [--user <user_email>] [--copy-source <source_email> --copy-dest <dest_email>] [--config <config.yaml>]
#
# .NOTES
#    - This script is licensed under the MIT License.
#

set -euo pipefail

# Disable history expansion (prevent issues with exclamation marks in credentials)
set +H

# --- Log level constants ---
readonly LOG_LEVEL_INFO=0
readonly LOG_LEVEL_DEBUG=1
readonly LOG_LEVEL_CRITICAL_DEBUG=2
readonly LOG_LEVEL_ULTIMATE_DEBUG=3

# Default log level - highest level (ULTIMATE_DEBUG)
# Change to LOG_LEVEL_INFO when development is completed
#LOG_LEVEL=$LOG_LEVEL_ULTIMATE_DEBUG
LOG_LEVEL=$LOG_LEVEL_INFO

# --- Logging functions (to stderr) ---
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - $1" >&2
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - $1" >&2
}

log_debug() {
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - DEBUG - $1" >&2
    fi
}

log_critical_debug() {
    if [ $LOG_LEVEL -ge $LOG_LEVEL_CRITICAL_DEBUG ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - CRITICAL DEBUG - $1" >&2
    fi
}

log_ultimate_debug() {
    if [ $LOG_LEVEL -ge $LOG_LEVEL_ULTIMATE_DEBUG ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ULTIMATE DEBUG - $1" >&2
    fi
}

# --- Parse command-line arguments ---
TARGET_USER=""
COPY_SOURCE=""
COPY_DEST=""
CONFIG_FILE="config.yaml"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --user)
            TARGET_USER="$2"
            shift 2;;
        --copy-source)
            COPY_SOURCE="$2"
            shift 2;;
        --copy-dest)
            COPY_DEST="$2"
            shift 2;;
        --config)
            CONFIG_FILE="$2"
            shift 2;;
        *)
            log_error "Unknown parameter passed: $1"
            exit 1;;
    esac
done

# --- Check for required tools ---
for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Command '$cmd' is required but not installed."
        exit 1
    fi
done

# --- Parse config file with hardcoded key extraction ---
parse_config() {
    local config_file=$1
    
    # Initialize variables with empty values
    APIURL=""
    ACCESS_TOKEN_URL=""
    CLIENTID=""
    CLIENTSECRET=""
    SUBACCOUNTID=""
    SKIP_USERS=()
    
    log_ultimate_debug "==== PARSING CONFIG FILE WITH DIRECT EXTRACTION ===="
    
    # Function to clean up values by removing quotes, CR, LF
    clean_value() {
        # Remove quotes, spaces, carriage returns, and line feeds
        local value="$1"
        value=$(echo -n "$value" | tr -d ' "\r\n')
        echo "$value"
    }

    # Extract values directly with grep
    log_ultimate_debug "Reading apiurl..."
    APIURL=$(grep -E "^apiurl:" "$config_file" | cut -d':' -f2-)
    APIURL=$(clean_value "$APIURL")
    log_ultimate_debug "APIURL='$APIURL'"
    
    log_ultimate_debug "Reading access_token_url..."
    ACCESS_TOKEN_URL=$(grep -E "^access_token_url:" "$config_file" | cut -d':' -f2-)
    ACCESS_TOKEN_URL=$(clean_value "$ACCESS_TOKEN_URL")
    log_ultimate_debug "ACCESS_TOKEN_URL='$ACCESS_TOKEN_URL'"
    
    log_ultimate_debug "Reading clientid..."
    CLIENTID=$(grep -E "^clientid:" "$config_file" | cut -d':' -f2-)
    CLIENTID=$(clean_value "$CLIENTID")
    log_ultimate_debug "CLIENTID='$CLIENTID'"
    
    log_ultimate_debug "Reading clientsecret..."
    CLIENTSECRET=$(grep -E "^clientsecret:" "$config_file" | cut -d':' -f2-)
    CLIENTSECRET=$(clean_value "$CLIENTSECRET")
    log_ultimate_debug "CLIENTSECRET='${CLIENTSECRET:0:3}...'"
    
    log_ultimate_debug "Reading subaccountid..."
    SUBACCOUNTID=$(grep -E "^subaccountid:" "$config_file" | cut -d':' -f2-)
    SUBACCOUNTID=$(clean_value "$SUBACCOUNTID")
    log_ultimate_debug "SUBACCOUNTID='$SUBACCOUNTID'"
    
    # Extract skip_users array
    log_ultimate_debug "Reading skip_users..."
    while read -r item; do
        if [[ -n "$item" ]]; then
            # Remove leading dash and whitespace
            user=$(echo "$item" | sed 's/^[[:space:]]*-[[:space:]]*//')
            user=$(clean_value "$user")
            SKIP_USERS+=("$user")
            log_ultimate_debug "Added skip_user='$user'"
        fi
    done < <(grep -A 10 "^skip_users:" "$config_file" | tail -n +2 | grep -E "^[[:space:]]*-")
    
    log_ultimate_debug "Parsing complete"
    
    # Ultimate debugging for configuration
    log_ultimate_debug "==== FULL CONFIGURATION AFTER PARSING ===="
    log_ultimate_debug "APIURL='$APIURL'"
    log_ultimate_debug "ACCESS_TOKEN_URL='$ACCESS_TOKEN_URL'"
    log_ultimate_debug "CLIENTID='$CLIENTID'"
    log_ultimate_debug "CLIENTSECRET='${CLIENTSECRET:0:3}...'"
    log_ultimate_debug "SUBACCOUNTID='$SUBACCOUNTID'"
    log_ultimate_debug "SKIP_USERS (${#SKIP_USERS[@]}):"
    for skip_user in "${SKIP_USERS[@]}"; do
        log_ultimate_debug "  - '$skip_user'"
    done
    log_ultimate_debug "========================================="
}

# --- Load configuration from YAML ---
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Configuration file '$CONFIG_FILE' not found."
    exit 1
fi

# Get access to the raw config file
log_ultimate_debug "====== Raw Config File Contents ======"
cat "$CONFIG_FILE" | while read line; do
    log_ultimate_debug "Line: $line"
done
log_ultimate_debug "======================================"

# Parse the config file
parse_config "$CONFIG_FILE"

# Debug the actual values only at ultimate debug level
if [ $LOG_LEVEL -ge $LOG_LEVEL_ULTIMATE_DEBUG ]; then
    log_ultimate_debug "Debug hex output of APIURL:"
    echo -n "$APIURL" | hexdump -C
fi

# Debug the final parsed values for validation
log_ultimate_debug "==== FINAL CONFIG VALUES BEFORE USE ===="
log_ultimate_debug "APIURL (final)='$APIURL'"
log_ultimate_debug "ACCESS_TOKEN_URL (final)='$ACCESS_TOKEN_URL'"
log_ultimate_debug "CLIENTID (final)='${CLIENTID:0:10}...'"
log_ultimate_debug "SUBACCOUNTID (final)='$SUBACCOUNTID'"
log_ultimate_debug "SKIP_USERS (final)=${SKIP_USERS[*]}"
log_ultimate_debug "========================================="

# Fallback to environment variables if needed.
CLIENTID=${CLIENTID:-$SAP_BTP_CLIENTID}
CLIENTSECRET=${CLIENTSECRET:-$SAP_BTP_CLIENTSECRET}

if [ -z "$CLIENTID" ] || [ -z "$CLIENTSECRET" ]; then
    log_error "Client credentials (clientid and clientsecret) are missing."
    exit 1
fi

# --- Helper: URL-encode a string (bash-only version) ---
urlencode() {
    local string="$1"
    # Start with common replacements
    string="${string// /%20}"      # space to %20
    string="${string//\"/%22}"     # " to %22
    string="${string//=/%3D}"      # = to %3D
    
    # Check if it's a filter expression (contains "eq")
    if [[ "$string" == *"eq"* ]]; then
        # Handle filter expression special characters
        string="${string//\(/%28}"    # ( to %28
        string="${string//\)/%29}"    # ) to %29
    fi
    
    echo "$string"
    
    # For future reference, more characters that might need encoding:
    # string="${string//!/%21}"      # ! to %21
    # string="${string//#/%23}"      # # to %23
    # string="${string//\$/%24}"     # $ to %24
    # string="${string//&/%26}"      # & to %26
    # string="${string//'/%27}"      # ' to %27
    # string="${string//+/%2B}"      # + to %2B
    # string="${string//,/%2C}"      # , to %2C
    # string="${string//\//%2F}"     # / to %2F
    # string="${string//:/%3A}"      # : to %3A
    # string="${string//;/%3B}"      # ; to %3B
    # string="${string//</%3C}"      # < to %3C
    # string="${string//>/%3E}"      # > to %3E
    # string="${string//\?/%3F}"     # ? to %3F
    # string="${string//\@/%40}"     # @ to %40
    # string="${string//\[/%5B}"     # [ to %5B
    # string="${string//\\/%5C}"     # \ to %5C
    # string="${string//\]/%5D}"     # ] to %5D
}

# --- Obtain OAuth token ---
ENCODED=$(printf '%s:%s' "$CLIENTID" "$CLIENTSECRET" | base64 -w 0)
log_info "Obtaining OAuth token..."
TOKEN_RESPONSE=$(curl -s --http1.1 -m 30 -w "\n%{http_code}" -X POST "$ACCESS_TOKEN_URL" \
  -H "Authorization: Basic $ENCODED" \
  -d 'grant_type=client_credentials' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json')
clean_token_response=$(echo "$TOKEN_RESPONSE" | sed 's/--http1\.1//g')
HTTP_STATUS=$(echo "$clean_token_response" | tail -n1 | tr -d '[:space:]')
TOKEN_BODY=$(echo "$clean_token_response" | sed '$d')

if [ "$HTTP_STATUS" -lt 200 ] || [ "$HTTP_STATUS" -ge 300 ]; then
    log_error "Failed to obtain OAuth token: HTTP $HTTP_STATUS"
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_BODY" | jq -r '.access_token')
if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    log_error "OAuth token not found in response."
    exit 1
fi
log_info "Successfully obtained OAuth token."

# --- Function: Get users by origin ---
get_users() {
    local origin="$1"
    local url="${APIURL%/}/Users"
    local filter="origin eq \"$origin\""
    local encoded_filter
    encoded_filter=$(urlencode "$filter")
    local full_url="${url}?filter=${encoded_filter}"
    local response
    
    log_debug "Fetching users from URL: $full_url"
    response=$(curl -s -X GET "$full_url" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
    
    # Check if response is valid JSON
    if ! echo "$response" | jq -e . >/dev/null 2>&1; then
        log_error "Invalid JSON response from API:"
        log_error "Raw response: $response"
        echo "{}"
        return 1
    fi
    
    local count
    count=$(echo "$response" | jq '.resources | length')
    log_info "Retrieved $count users from $origin"
    
    echo "$response" | jq 'reduce .resources[] as $user ({}; 
        if ($user | type == "object" and ($user.emails? and ($user.emails | length > 0) and (($user.emails[0].value) | type == "string")))
        then . + {($user.emails[0].value | ascii_downcase): $user}
        else . end)'
}

# --- Function: Create a custom user based on a default user ---
create_custom_user() {
    local user_json="$1"
    if [ "$(echo "$user_json" | jq -r 'type')" != "object" ]; then
        log_error "User JSON is not an object; skipping creation."
        return
    fi

    local userName email payload url response clean_response http_status
    userName=$(echo "$user_json" | jq -r '.userName')
    email=$(echo "$user_json" | jq -r '.emails[0].value')
    payload=$(jq -n \
      --arg userName "$userName" \
      --arg email "$email" \
      --arg zoneId "$SUBACCOUNTID" \
      '{
          userName: $userName,
          emails: [{value: $email, primary: false}],
          origin: "sap.custom",
          zoneId: $zoneId,
          schemas: ["urn:scim:schemas:core:1.0"]
      }')
    url="${APIURL%/}/Users"
    response=$(curl -s --http1.1 -w "\n%{http_code}" -X POST "$url" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json" \
      -H "Content-Type: application/json" \
      -d "$payload")
    clean_response=$(echo "$response" | sed 's/--http1\.1//g')
    http_status=$(echo "$clean_response" | tail -n1 | tr -d '[:space:]')
    if [ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ]; then
        log_info "Created custom user: $userName"
    else
        log_error "Failed to create custom user $userName: HTTP $http_status"
    fi
}

# --- Function: Retrieve all role collections ---
get_role_collections() {
    local url="${APIURL%/}/Groups"
    local response
    response=$(curl -s -X GET "$url" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
    local count
    count=$(echo "$response" | jq '(.resources | length)')
    ROLE_COLLECTIONS=$(echo "$response" | jq 'reduce .resources[] as $role ({}; . + {($role.id): $role})')
    log_info "Retrieved $count role collections"
}

# --- Function: Assign a role to a user ---
assign_role_to_user() {
    local role_id="$1" user_id="$2" user_email="$3" user_origin="${4:-sap.custom}"
    local payload url encoded_role response clean_response http_status
    
    log_debug "Attempting to assign role $role_id to user $user_email ($user_id, origin: $user_origin)"
    
    # Check if role exists in role collections
    if ! echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role_id" 'has($role)' &>/dev/null; then
        log_debug "Role $role_id not found in role collections"
        return 1
    fi
    
    payload=$(jq -n --arg user_id "$user_id" --arg origin "$user_origin" '{
        origin: $origin,
        type: "USER",
        value: $user_id
    }')
    log_debug "Role assignment payload: $(echo "$payload" | jq -c '.')"
    
    # URL encode the role ID - CRITICAL FIX 
    local encoded_role
    encoded_role=$(urlencode "$role_id")
    log_critical_debug "URL encoded role ID: $encoded_role"
    
    url="${APIURL%/}/Groups/${encoded_role}/members"
    log_debug "Role assignment URL: $url"
    
    response=$(curl -s --http1.1 -w "\n%{http_code}" -X POST "$url" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json" \
      -H "Content-Type: application/json" \
      -d "$payload")
    clean_response=$(echo "$response" | sed 's/--http1\.1//g')
    http_status=$(echo "$clean_response" | tail -n1 | tr -d '[:space:]')
    
    log_debug "Role assignment response status: $http_status"
    log_debug "Role assignment response body: $(echo "$clean_response" | sed '$d' | jq -c '.' 2>/dev/null || echo "Not JSON")"
    
    if [ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ]; then
        log_info "Assigned role '$role_id' to user $user_email ($user_origin)"
        return 0
    else
        log_error "Failed to assign role '$role_id' to user $user_email ($user_origin): HTTP $http_status"
        return 1
    fi
}

# --- Function: Remove a role from a user ---
remove_role_from_user() {
    local role_id="$1" user_id="$2" user_email="$3" user_origin="${4:-sap.custom}"
    local url response clean_response http_status
    
    log_debug "Attempting to remove role $role_id from user $user_email ($user_id, origin: $user_origin)"
    
    # Check if role exists in role collections
    if ! echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role_id" 'has($role)' &>/dev/null; then
        log_debug "Role $role_id not found in role collections"
        return 1
    fi
    
    # CRITICAL DEBUG: Dump ROLE_COLLECTIONS for this role
    log_critical_debug "Role collection for $role_id: $(echo "$ROLE_COLLECTIONS" | jq --arg role "$role_id" '.[$role]' | jq -c '.')"
    
    # URL encode the role ID - CRITICAL FIX
    local encoded_role_id
    encoded_role_id=$(urlencode "$role_id")
    log_critical_debug "URL encoded role ID: $encoded_role_id"
    
    # Get all members of the role to find the correct member ID to remove
    url="${APIURL%/}/Groups/${encoded_role_id}/members"
    log_debug "Getting role members URL: $url"
    
    members_response=$(curl -s -w "\n%{http_code}" -X GET "$url" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Accept: application/json")
      
    # Get HTTP status code from the last line
    http_status=$(echo "$members_response" | tail -n1 | tr -d '[:space:]')
    # Remove the status code line to get just the response body
    members_body=$(echo "$members_response" | sed '$d')
    
    # CRITICAL DEBUG: Show raw response
    log_critical_debug "Role members raw response: $members_body"
    log_critical_debug "Role members HTTP status: $http_status"
    
    # Check if response is valid
    if [ "$http_status" -lt 200 ] || [ "$http_status" -ge 300 ]; then
        log_error "Failed to get role members: HTTP $http_status"
        log_error "Response: $members_body"
        return 1
    fi
    
    # Try to parse as JSON
    if ! echo "$members_body" | jq -e . >/dev/null 2>&1; then
        log_error "Failed to parse role members response as JSON"
        return 1
    fi

    # Check if response is a direct array (no resources property) or an object with resources
    is_array=$(echo "$members_body" | jq -r 'if type=="array" then "true" else "false" end')
    
    # CRITICAL DEBUG: Dump members response
    if [ "$is_array" = "true" ]; then
        log_critical_debug "All members of role $role_id (direct array format): $(echo "$members_body" | jq -c '.')"
        # For direct array format, look for a member with matching value and origin
        members_array="$members_body"
    else
        log_critical_debug "All members of role $role_id (resources format): $(echo "$members_body" | jq -c '.resources // []')"
        # For resources format, extract the resources array
        members_array=$(echo "$members_body" | jq -c '.resources // []')
    fi
    
    # Find the specific member ID for this user in this role
    if [ "$is_array" = "true" ]; then
        # Direct array format - find matching value and origin
        log_critical_debug "Looking for user with value=$user_id and origin=$user_origin in direct array"
        member_data=$(echo "$members_array" | jq -r --arg uid "$user_id" --arg org "$user_origin" \
          '.[] | select(.value == $uid and .origin == $org)')
        
        # Extract member id if available, or default to empty
        member_id=$(echo "$member_data" | jq -r '.id // empty')
        
        # If there's no id property in the data (API sometimes omits it), we'll use the index as an identifier
        if [ -z "$member_id" ] && [ -n "$member_data" ]; then
            log_critical_debug "Member found but no ID property - using array index"
            # Find index in the array without using input_index which is not available in all jq versions
            member_index=$(echo "$members_array" | jq --arg uid "$user_id" --arg org "$user_origin" \
              'to_entries | map(select(.value.value == $uid and .value.origin == $org)) | first | .key')
            if [ -n "$member_index" ] && [ "$member_index" != "null" ]; then
                member_id="$member_index"
                log_critical_debug "Using index $member_id as member identifier"
            fi
        fi
    else
        # Resources format - traditional lookup
        member_id=$(echo "$members_body" | jq -r --arg uid "$user_id" --arg org "$user_origin" \
          '.resources[] | select(.value == $uid and .origin == $org) | .id // empty')
    fi
    
    if [ -z "$member_id" ]; then
        log_debug "User $user_email ($user_id) is not a member of role $role_id"
        
        # CRITICAL: Try looking up without origin requirement
        log_critical_debug "Attempting to find member without origin requirement"
        
        if [ "$is_array" = "true" ]; then
            # Direct array format - try without origin
            log_critical_debug "Looking for user with just value=$user_id in direct array (no origin check)"
            member_data=$(echo "$members_array" | jq -r --arg uid "$user_id" \
              '.[] | select(.value == $uid)')
            
            # Extract member id if available, or default to empty
            member_id=$(echo "$member_data" | jq -r '.id // empty')
            
            # If there's no id property in the data (API sometimes omits it), check if we found a member at all
            if [ -z "$member_id" ] && [ -n "$member_data" ]; then
                log_critical_debug "Member found without origin check but no ID property"
                
                # Extract the value and origin to confirm the match
                found_value=$(echo "$member_data" | jq -r '.value // empty')
                found_origin=$(echo "$member_data" | jq -r '.origin // empty')
                
                if [ "$found_value" = "$user_id" ]; then
                    log_critical_debug "Found a direct match for value: $found_value (origin: $found_origin)"
                    
                    # Try to get the index if possible
                    member_index=$(echo "$members_array" | jq --arg uid "$user_id" \
                      'to_entries | map(select(.value.value == $uid)) | first | .key')
                      
                    if [ -n "$member_index" ] && [ "$member_index" != "null" ]; then
                        member_id="$member_index"
                        log_critical_debug "Using index $member_id as member identifier for non-origin match"
                    else
                        # Use the raw user data in our delete request instead of an ID
                        member_id="raw_data:$found_value:$found_origin"
                    fi
                fi
            fi
        else
            # Resources format - try without origin requirement
            member_id=$(echo "$members_body" | jq -r --arg uid "$user_id" \
              '.resources[] | select(.value == $uid) | .id // empty')
        fi
        
        if [ -z "$member_id" ]; then
            log_critical_debug "User not found as member in any origin"
            return 1
        else
            log_critical_debug "Found member ID $member_id for user $user_email in role $role_id (ignoring origin)"
        fi
    else
        log_debug "Found member ID $member_id for user $user_email in role $role_id"
    fi
    
    # Now delete the specific member using the encoded role ID
    if [[ "$member_id" == raw_data:* ]] || [[ "$member_id" =~ ^[0-9]+$ ]]; then
        # If member_id is numeric or raw_data format, use PUT to update the entire collection
        if [[ "$member_id" == raw_data:* ]]; then
            # Extract the value and origin from the raw data format
            IFS=':' read -r _ raw_value raw_origin <<< "$member_id"
            log_critical_debug "Using raw data for member deletion: value=$raw_value, origin=$raw_origin"
            
            # Get the current members without the user we want to remove
            updated_members=$(echo "$members_array" | jq -c --arg val "$raw_value" --arg org "$raw_origin" \
              '[.[] | select(.value != $val or .origin != $org)]')
        else
            # Using numeric index to remove the member at that position
            log_critical_debug "Using numeric index $member_id for member deletion"
            
            # Get the current members without the member at the specified index
            updated_members=$(echo "$members_array" | jq -c --arg idx "$member_id" \
              'del(.[$idx | tonumber])')
        fi
          
        log_debug "Current members count: $(echo "$members_array" | jq 'length')"
        log_debug "Updated members count: $(echo "$updated_members" | jq 'length')"
        
        # Get the full role collection data
        role_data=$(echo "$ROLE_COLLECTIONS" | jq --arg role "$role_id" '.[$role]')
        
        # Create updated role collection (replacing members array)
        updated_role=$(echo "$role_data" | jq --argjson members "$updated_members" '.members = $members')
        
        # Issue PUT request to update the role collection
        url="${APIURL%/}/Groups/${encoded_role_id}"
        log_debug "Role update URL: $url"
        
        # Extract the version for If-Match header
        version=$(echo "$role_data" | jq -r '.meta.version')
        log_critical_debug "Using meta.version=$version for If-Match header"
        
        response=$(curl -s --http1.1 -w "\n%{http_code}" -X PUT "$url" \
          -H "Authorization: Bearer $ACCESS_TOKEN" \
          -H "Accept: application/json" \
          -H "Content-Type: application/json" \
          -H "If-Match: $version" \
          -d "$updated_role")
    else
        # Standard approach with member ID in URL (only when we have a real ID, not an index)
        url="${APIURL%/}/Groups/${encoded_role_id}/members/${member_id}"
        log_debug "Role removal URL: $url"
        
        response=$(curl -s --http1.1 -w "\n%{http_code}" -X DELETE "$url" \
          -H "Authorization: Bearer $ACCESS_TOKEN" \
          -H "Accept: application/json")
    fi
    
    # Process the response
    clean_response=$(echo "$response" | sed 's/--http1\.1//g')
    http_status=$(echo "$clean_response" | tail -n1 | tr -d '[:space:]')
    
    log_debug "Role removal response status: $http_status"
    log_debug "Role removal response body: $(echo "$clean_response" | sed '$d' | jq -c '.' 2>/dev/null || echo "Not JSON")"
    
    if [ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ]; then
        log_info "Removed role '$role_id' from user $user_email ($user_origin)"
        return 0
    else
        log_error "Failed to remove role '$role_id' from user $user_email ($user_origin): HTTP $http_status"
        return 1
    fi
}

# --- Function: Synchronize users and roles ---
sync_users_and_roles() {
    local target_email="$1"
    if [ -n "$target_email" ]; then
        target_email=$(echo "$target_email" | tr '[:upper:]' '[:lower:]' | xargs)
    fi

    declare -A skip
    for u in "${SKIP_USERS[@]}"; do
        u=$(echo "$u" | tr '[:upper:]' '[:lower:]' | xargs)
        skip["$u"]=1
    done

    local default_users_json custom_users_json
    default_users_json=$(get_users "sap.default")
    custom_users_json=$(get_users "sap.custom")

    if [ -n "$target_email" ]; then
        if [[ ${skip[$target_email]:-} ]]; then
            log_info "Skipping synchronization for target user: $target_email"
            return
        fi
        default_users_json=$(echo "$default_users_json" | jq --arg email "$target_email" 'if has($email) then {($email): .[$email]} else {} end')
        custom_users_json=$(echo "$custom_users_json" | jq --arg email "$target_email" 'if has($email) then {($email): .[$email]} else {} end')
    else
        local skip_array
        skip_array=$(printf '"%s",' "${!skip[@]}")
        skip_array="[${skip_array%,}]"
        default_users_json=$(echo "$default_users_json" | jq --argjson skip "$skip_array" 'with_entries(select((.key | ascii_downcase) as $email | ($skip | index($email)) == null))')
        custom_users_json=$(echo "$custom_users_json" | jq --argjson skip "$skip_array" 'with_entries(select((.key | ascii_downcase) as $email | ($skip | index($email)) == null))')
    fi

    for email in $(echo "$default_users_json" | jq -r 'keys[]'); do
        if ! echo "$custom_users_json" | jq --exit-status --arg email "$email" 'has($email)' &>/dev/null; then
            local user_json
            user_json=$(echo "$default_users_json" | jq --arg email "$email" '.[$email]')
            create_custom_user "$user_json"
        fi
    done

    custom_users_json=$(get_users "sap.custom")
    if [ -n "$target_email" ]; then
        custom_users_json=$(echo "$custom_users_json" | jq --arg email "$target_email" 'if has($email) then {($email): .[$email]} else {} end')
    else
        local skip_array
        skip_array=$(printf '"%s",' "${!skip[@]}")
        skip_array="[${skip_array%,}]"
        custom_users_json=$(echo "$custom_users_json" | jq --argjson skip "$skip_array" 'with_entries(select((.key | ascii_downcase) as $email | ($skip | index($email)) == null))')
    fi

    get_role_collections

    for email in $(echo "$default_users_json" | jq -r 'keys[]'); do
        if echo "$custom_users_json" | jq --exit-status --arg email "$email" 'has($email)' &>/dev/null; then
            local default_user custom_user default_roles custom_roles
            default_user=$(echo "$default_users_json" | jq --arg email "$email" '.[$email]')
            custom_user=$(echo "$custom_users_json" | jq --arg email "$email" '.[$email]')
            default_roles=$(echo "$default_user" | jq '[.groups[]?.value] | unique')
            custom_roles=$(echo "$custom_user" | jq '[.groups[]?.value] | unique')

            local missing_roles extra_roles
            missing_roles=$(echo "$default_roles" | jq --argjson c "$custom_roles" 'map(select(. as $item | $c | index($item) | not))')
            extra_roles=$(echo "$custom_roles" | jq --argjson d "$default_roles" 'map(select(. as $item | $d | index($item) | not))')

            mapfile -t missing_roles_array < <(echo "$missing_roles" | jq -r '.[]')
            for role in "${missing_roles_array[@]}"; do
                group_id=$(echo "$ROLE_COLLECTIONS" | jq -r --arg role "$role" 'to_entries[] | select(.key == $role) | .key' | head -n1)
                if [ -n "$group_id" ]; then
                    user_id=$(echo "$custom_user" | jq -r '.id')
                    # Origin is sap.custom for custom users
                    assign_role_to_user "$group_id" "$user_id" "$email" "sap.custom"
                else
                    log_error "Role '$role' not found in ROLE_COLLECTIONS"
                fi
            done

            # Read roles into array properly with mapfile to preserve spaces in role names
            mapfile -t extra_roles_array < <(echo "$extra_roles" | jq -r '.[]')
            for role in "${extra_roles_array[@]}"; do
                if echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role" 'has($role)' &>/dev/null; then
                    local user_id
                    user_id=$(echo "$custom_user" | jq -r '.id')
                    # Origin is sap.custom for custom users
                    remove_role_from_user "$role" "$user_id" "$email" "sap.custom"
                fi
            done
        fi
    done
}

# --- Function: Copy role assignments from one user to another ---
copy_role_assignments() {
    local source_email dest_email
    source_email=$(echo "$1" | tr '[:upper:]' '[:lower:]' | xargs)
    dest_email=$(echo "$2" | tr '[:upper:]' '[:lower:]' | xargs)

    local default_users_all_json custom_users_all_json
    default_users_all_json=$(get_users "sap.default")
    custom_users_all_json=$(get_users "sap.custom")

    if ! echo "$default_users_all_json" | jq --exit-status --arg email "$source_email" 'has($email)' &>/dev/null; then
        log_error "Source default user $source_email not found"
        return 1
    fi
    if ! echo "$default_users_all_json" | jq --exit-status --arg email "$dest_email" 'has($email)' &>/dev/null; then
        log_error "Destination default user $dest_email not found"
        return 1
    fi

    local source_default dest_default
    source_default=$(echo "$default_users_all_json" | jq --arg email "$source_email" '.[$email]')
    dest_default=$(echo "$default_users_all_json" | jq --arg email "$dest_email" '.[$email]')

    # DEBUG: Output users info
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        log_debug "Source default user info:"
        echo "$source_default" | jq -c '.' >&2
        log_debug "Destination default user info:"
        echo "$dest_default" | jq -c '.' >&2
    fi

    local source_roles_default dest_roles_default
    source_roles_default=$(echo "$source_default" | jq '[.groups[]?.value] | unique')
    dest_roles_default=$(echo "$dest_default" | jq '[.groups[]?.value] | unique')

    # DEBUG: Output role info for default users
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        log_debug "Source default user roles:"
        echo "$source_roles_default" | jq -c '.' >&2
        log_debug "Destination default user roles:"
        echo "$dest_roles_default" | jq -c '.' >&2
    fi

    get_role_collections
    log_debug "Retrieved $(echo "$ROLE_COLLECTIONS" | jq 'length') role collections"

    # Correctly compare arrays with jq to find roles to add and remove
    local missing_roles extra_roles
    missing_roles=$(echo "$source_roles_default" | jq --argjson dest "$dest_roles_default" '[.[] | select(. as $src | $dest | index($src) | not)]')
    extra_roles=$(echo "$dest_roles_default" | jq --argjson src "$source_roles_default" '[.[] | select(. as $dest | $src | index($dest) | not)]')
    
    # DEBUG: Output role differences for default users
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        log_debug "Roles to add to destination default user:"
        echo "$missing_roles" | jq -c '.' >&2
        log_debug "Roles to remove from destination default user:"
        echo "$extra_roles" | jq -c '.' >&2
    fi

    # CRITICAL DEBUG: How many roles to add?
    log_critical_debug "Found $(echo "$missing_roles" | jq '. | length') roles to add to default user"
    
    # Add roles that source has but destination doesn't
    # Read roles into array properly with mapfile to preserve spaces in role names
    mapfile -t roles_to_add < <(echo "$missing_roles" | jq -r '.[]')
    for role in "${roles_to_add[@]}"; do
        log_critical_debug "Processing role to add: $role"
        if echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role" 'has($role)' &>/dev/null; then
            local dest_default_id
            dest_default_id=$(echo "$dest_default" | jq -r '.id')
            log_critical_debug "About to add role $role to default user $dest_email (id: $dest_default_id)"
            # Pass the correct origin (sap.default) for default users
            assign_role_to_user "$role" "$dest_default_id" "$dest_email" "sap.default"
        else
            log_critical_debug "Role $role not found in ROLE_COLLECTIONS"
        fi
    done
    
    # CRITICAL DEBUG: How many roles to remove?
    log_critical_debug "Found $(echo "$extra_roles" | jq '. | length') roles to remove from default user"

    # ULTIMATE DEBUG: Dump all role collections
    log_ultimate_debug "All available role collections:"
    echo "$ROLE_COLLECTIONS" | jq -r 'keys[]' | while read -r role_key; do
        log_ultimate_debug "Role collection '$role_key' exists"
    done

    # Remove roles that destination has but source doesn't
    # Read roles into array properly with mapfile to preserve spaces in role names
    mapfile -t roles_to_remove < <(echo "$extra_roles" | jq -r '.[]')
    for role in "${roles_to_remove[@]}"; do
        log_critical_debug "Processing role to remove: $role"
        
        # ULTIMATE DEBUG: Check if role exists and show comparison
        if echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role" 'has($role)' &>/dev/null; then
            log_ultimate_debug "Role '$role' found in ROLE_COLLECTIONS"
            local dest_default_id
            dest_default_id=$(echo "$dest_default" | jq -r '.id')
            log_critical_debug "About to remove role $role from default user $dest_email (id: $dest_default_id)"
            # Pass the correct origin (sap.default) for default users
            if remove_role_from_user "$role" "$dest_default_id" "$dest_email" "sap.default"; then
                log_ultimate_debug "Successfully removed role $role"
            else
                log_ultimate_debug "Failed to remove role $role"
            fi
        else
            log_critical_debug "Role $role not found in ROLE_COLLECTIONS"
            # ULTIMATE DEBUG: Try to find similar role names
            log_ultimate_debug "Searching for similar role names to '$role':"
            echo "$ROLE_COLLECTIONS" | jq -r 'keys[]' | grep -i "$role" || echo "No similar roles found"
        fi
    done

    if ! echo "$custom_users_all_json" | jq --exit-status --arg email "$dest_email" 'has($email)' &>/dev/null; then
        create_custom_user "$dest_default"
        custom_users_all_json=$(get_users "sap.custom")
    fi
    if ! echo "$custom_users_all_json" | jq --exit-status --arg email "$dest_email" 'has($email)' &>/dev/null; then
        log_error "Destination custom user $dest_email not found even after creation"
        return 1
    fi
    local dest_custom
    dest_custom=$(echo "$custom_users_all_json" | jq --arg email "$dest_email" '.[$email]')

    # DEBUG: Output for diagnosis
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        log_debug "User info for destination custom user:"
        echo "$dest_custom" | jq -c '.' >&2
    fi
    
    # Get source and destination roles for custom user
    # Important: We're copying roles from source default user to destination custom user
    local source_roles_custom dest_roles_custom
    source_roles_custom=$(echo "$source_default" | jq '[.groups[]?.value] | unique')
    dest_roles_custom=$(echo "$dest_custom" | jq '[.groups[]?.value] | unique')
    
    # DEBUG: Output roles for diagnosis
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        log_debug "Source roles (from default user):"
        echo "$source_roles_custom" | jq -c '.' >&2
        log_debug "Destination custom user roles:"
        echo "$dest_roles_custom" | jq -c '.' >&2
    fi

    # Correctly compare arrays with jq to find roles to add and remove for custom user
    local missing_roles_custom extra_roles_custom
    missing_roles_custom=$(echo "$source_roles_custom" | jq --argjson dest "$dest_roles_custom" '[.[] | select(. as $src | $dest | index($src) | not)]')
    extra_roles_custom=$(echo "$dest_roles_custom" | jq --argjson src "$source_roles_custom" '[.[] | select(. as $dest | $src | index($dest) | not)]')
    
    # DEBUG: Output role differences for diagnosis
    if [ $LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        log_debug "Roles to add to destination custom user:"
        echo "$missing_roles_custom" | jq -c '.' >&2
        log_debug "Roles to remove from destination custom user:"
        echo "$extra_roles_custom" | jq -c '.' >&2
    fi

    # CRITICAL DEBUG: How many roles to add to custom user?
    log_critical_debug "Found $(echo "$missing_roles_custom" | jq '. | length') roles to add to custom user"
    
    # ULTIMATE DEBUG: Dump all role collections again for custom user
    log_ultimate_debug "All available role collections for custom user:"
    echo "$ROLE_COLLECTIONS" | jq -r 'keys[]' | while read -r role_key; do
        log_ultimate_debug "Role collection '$role_key' exists for custom user"
    done
    
    # Add missing roles to custom user
    # Read roles into array properly with mapfile to preserve spaces in role names
    mapfile -t custom_roles_to_add < <(echo "$missing_roles_custom" | jq -r '.[]')
    for role in "${custom_roles_to_add[@]}"; do
        log_critical_debug "Processing role to add to custom user: $role"
        if echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role" 'has($role)' &>/dev/null; then
            log_ultimate_debug "Role '$role' found in ROLE_COLLECTIONS for custom user"
            local dest_custom_id
            dest_custom_id=$(echo "$dest_custom" | jq -r '.id')
            log_critical_debug "About to add role $role to custom user $dest_email (id: $dest_custom_id)"
            # Origin is sap.custom for custom users
            if assign_role_to_user "$role" "$dest_custom_id" "$dest_email" "sap.custom"; then
                log_ultimate_debug "Successfully added role $role to custom user"
            else
                log_ultimate_debug "Failed to add role $role to custom user"
            fi
        else
            log_critical_debug "Role $role not found in ROLE_COLLECTIONS for custom user"
            # ULTIMATE DEBUG: Try to find similar role names
            log_ultimate_debug "Searching for similar role names to '$role' for custom user:"
            echo "$ROLE_COLLECTIONS" | jq -r 'keys[]' | grep -i "$role" || echo "No similar roles found"
        fi
    done
    
    # CRITICAL DEBUG: How many roles to remove from custom user?
    log_critical_debug "Found $(echo "$extra_roles_custom" | jq '. | length') roles to remove from custom user"
    
    # Remove extra roles from custom user
    # Read roles into array properly with mapfile to preserve spaces in role names
    mapfile -t custom_roles_to_remove < <(echo "$extra_roles_custom" | jq -r '.[]')
    for role in "${custom_roles_to_remove[@]}"; do
        log_critical_debug "Processing role to remove from custom user: $role"
        if echo "$ROLE_COLLECTIONS" | jq --exit-status --arg role "$role" 'has($role)' &>/dev/null; then
            log_ultimate_debug "Role '$role' found in ROLE_COLLECTIONS for removal from custom user"
            local dest_custom_id
            dest_custom_id=$(echo "$dest_custom" | jq -r '.id')
            log_critical_debug "About to remove role $role from custom user $dest_email (id: $dest_custom_id)"
            # Origin is sap.custom for custom users
            if remove_role_from_user "$role" "$dest_custom_id" "$dest_email" "sap.custom"; then
                log_ultimate_debug "Successfully removed role $role from custom user"
            else
                log_ultimate_debug "Failed to remove role $role from custom user"
            fi
        else
            log_critical_debug "Role $role not found in ROLE_COLLECTIONS for custom user removal"
            # ULTIMATE DEBUG: Try to find similar role names
            log_ultimate_debug "Searching for similar role names to '$role' for custom user removal:"
            echo "$ROLE_COLLECTIONS" | jq -r 'keys[]' | grep -i "$role" || echo "No similar roles found"
        fi
    done
}

# --- Main execution ---
main() {
    if [ -n "$COPY_SOURCE" ] && [ -n "$COPY_DEST" ]; then
        copy_role_assignments "$COPY_SOURCE" "$COPY_DEST"
    else
        sync_users_and_roles "$TARGET_USER"
    fi
    log_info "Synchronization completed successfully"
}

main
