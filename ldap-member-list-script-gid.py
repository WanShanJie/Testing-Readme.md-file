#!/usr/bin/env python3

"""
Purpose: The LDAP_Member_List script is used to retrieve LDAP members in GID only
Usage: python3 /etc/zabbix/externalscripts/ldap-member-list-script-gid.py -l -f /etc/zabbix/externalscripts/zabbix-ldap.conf
Modify: 2025-Jul-17 Wan

"""
import random
import string
import configparser
import sys
import ldap
import ldap.filter
import time
from datetime import datetime


# stop the insecure SSL cert warnings for ldap
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from docopt import docopt
from pathlib import Path

LDAP_API_Call = 0

LDAP_ENCODING = 'utf-8'
class LDAPConn(object):
    """
    LDAP connector class
    Defines methods for retrieving users and groups from LDAP server.
    """

    def __init__(self, uri, base, user, passwd):
        self.uri   = uri
        self.base  = base
        self.ldap_user  = user
        self.ldap_pass  = passwd
        self.conn = None

    def connect(self):
        """ Establish a connection to the LDAP server. """
        try:
            # Ignore certificate errors for LDAPS
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            self.conn = ldap.initialize(self.uri) # Initialize connection to LDAP AD server
            self.conn.set_option(ldap.OPT_REFERRALS, 0) # Disable automatic referral chasing (server not answer, go to ask another server)
            self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3) # AD needs LDAP v3
            self.conn.simple_bind_s(self.ldap_user, self.ldap_pass) # Authenticate (bind) to AD
            print(f">>> Successfully connected to LDAP server: {self.uri}")
            return 1
        except ldap.LDAPError as e:
            if isinstance(e, ldap.INVALID_CREDENTIALS):
                print(f"LDAP Error: Invalid credentials for bind user {self.ldap_user}")
            elif isinstance(e, ldap.SERVER_DOWN):
                print(f"LDAP Error: Cannot connect to LDAP server {self.uri}: {e}")
            else:
                print(f"LDAP General Error: {e}")
            sys.exit()

    def disconnect(self):
        """ Disconnect from the LDAP server. """
        if self.conn:
            self.conn.unbind_s()

    def get_users_attributes(self, usernames, attributes):
        """
        Fetches multiple attributes for multiple users in a single LDAP call
        Args:
            usernames: List of usernames to fetch
            attributes: List of attributes to fetch
        Returns:
            Dict of {username: {attribute: value}} for all users
        """
        global LDAP_API_Call

        if not usernames:
            return {}

        # Build filter for all users (OR condition)
        user_filters = []
        for username in usernames:
            escaped = ldap.filter.escape_filter_chars(username)
            user_filters.append(f"(sAMAccountName={escaped})")
        combined_filter = f"(|{''.join(user_filters)})"

        base_str = self.base.decode(LDAP_ENCODING) if isinstance(self.base, bytes) else self.base

        LDAP_API_Call +=1
        try:
            # Single API call to fetch all users and attributes
            results = self.conn.search_s(
                base= base_str,
                scope=ldap.SCOPE_SUBTREE,
                filterstr=combined_filter,
                attrlist = list(set(attributes + ['sAMAccountName']))
            )
            if not results:
                return {}

            # Process results into username->attributes mapping
            user_data = {}
            for dn, attrs in results:
                if not dn or not isinstance(dn, str):
                    continue  # Skip if dn is None or not a string

                # Use sAMAccountName to get username
                username = attrs.get('sAMAccountName', [b''])[0]
                if isinstance(username, bytes):
                    username = username.decode(LDAP_ENCODING)

                if not username:
                    continue

                # Prepare attribute dictionary
                user_attrs = {}
                for attr in attributes:
                    if attr in attrs:
                        value = attrs[attr][0]
                        if isinstance(value, bytes):
                            value = value.decode(LDAP_ENCODING)
                        user_attrs[attr] = value

                user_data[username] = user_attrs
            
            # print ("    LDAP_API_Call", LDAP_API_Call, "in get_users_attributes function")
            return user_data
            
        except ldap.LDAPError as e:
            print(f"LDAP lookup failed: {e}")
            return {}

    def get_group_members(self, group):

        """
        Retrieves members of one or more LDAP groups with optimized API usage.
        """
        global LDAP_API_Call, group_filter, group_member_attribute, active_directory, lowercase, uid_attribute, LDAP_ENCODING

        # Build combined group filter
        search_filters = []
        for group_name in group:
            # Escapes any special characters & string sustitution 
            search_filter = group_filter % ldap.filter.escape_filter_chars(group_name) 
            search_filters.append(search_filter)

        # Pass single filter to 'filterstr', & LDAP server will return all matching groups in one API call
        combined_filter = '(|' + ''.join(search_filters) + ')'

        # Query LDAP for group entries
        base_str = self.base.decode(LDAP_ENCODING) if isinstance(self.base, bytes) else self.base
        group_member_attr = group_member_attribute.decode(LDAP_ENCODING) if isinstance(group_member_attribute, bytes) else group_member_attribute

        # API call to retrieve the all data [('CN=ldapgroupname,...'),{'member': [b'...]}]
        LDAP_API_Call +=1
        try:
            group_results = self.conn.search_s(
                base=base_str,
                scope=ldap.SCOPE_SUBTREE,
                filterstr=combined_filter,
                attrlist=[group_member_attr] # member
            )

        except ldap.LDAPError as e:
            print(f"[ERROR] LDAP group search failed: {e}")
            return None

        if not group_results:
            print("[INFO] No groups found or members missing.")
            return []

        # Collect member DNs (in bytes) - extract members {'ldapgroupname':['CN=member,...'],...}
        all_member_dns = {}
        for dn, attrs in group_results:
            if not dn or group_member_attr not in attrs:
                continue
            
            group_name = None
            for part in dn.split(','):
                if part.strip().startswith('CN='):
                    group_name = part.split('=', 1)[1].strip()
                    break

            if not group_name:
                continue  # skip if we can't extract group name

            member_dns = [dn.decode(LDAP_ENCODING) for dn in attrs[group_member_attr]]
            all_member_dns[group_name] = member_dns

        if not all_member_dns:
            print("[INFO] No members found in any group.")
            return []


        final_members = {}
        # Resolve members after fetching the group_member_attribute (member)
        if active_directory:
            uid_attr_str = uid_attribute.decode(LDAP_ENCODING) if isinstance(uid_attribute, bytes) else uid_attribute

            # Build combined user filter
            user_filters = []
            for group_name, member_dns_list in all_member_dns.items():
                for dn in member_dns_list:
                    dn_str = dn.decode(LDAP_ENCODING) if isinstance(dn, bytes) else dn
                    user_filters.append(f"(distinguishedName={ldap.filter.escape_filter_chars(dn_str)})")

            #(|(distinguishedName = CN=member,...),...)
            combined_user_filter = '(|' + ''.join(user_filters) + ')' 

            #[('CN=member,...',{'sAMAccountName': [b'...']}),...]
            LDAP_API_Call +=1
            try:
                user_results = self.conn.search_s(
                    base=base_str,
                    scope=ldap.SCOPE_SUBTREE,
                    filterstr= combined_user_filter,
                    attrlist=[uid_attr_str] #sAMAccountName
                )
            except ldap.LDAPError as e:
                print(f"[ERROR] LDAP user resolution failed: {e}")
                return []

            # Create mapping of DN to username
            dn_to_username = {}
            for user_dn, user_attrs in user_results:
                if uid_attr_str in user_attrs:
                    username = user_attrs[uid_attr_str][0]
                    if isinstance(username, bytes):
                        username = username.decode(LDAP_ENCODING)
                    dn_to_username[user_dn] = username.lower() if lowercase else username

            # Map usernames back to their groups
            for group_name, member_dns in all_member_dns.items():
                final_members[group_name] = []
                for dn in member_dns:
                    if dn in dn_to_username:
                        final_members[group_name].append(dn_to_username[dn])        

        else:
            # Non-AD case: extract UID from DN without extra API calls
            for member_dn in all_member_dns:
                dn_str = member_dn.decode(LDAP_ENCODING) if isinstance(member_dn, bytes) else member_dn
                try:
                    uid_part = dn_str.split(',')[0]
                    if uid_part.startswith('uid='):
                        username = uid_part.split('=')[1]
                        final_members.append(username.lower() if lowercase else username)
                    else:
                        final_members.append(dn_str.lower() if lowercase else dn_str)
                except IndexError:
                    final_members.append(dn_str.lower() if lowercase else dn_str)
        
        # print ("    LDAP_API_Call", LDAP_API_Call, "in get_group_members function")
        return final_members


class LDAPConf(object):
    """
    Zabbix-LDAP configuration class
    Provides methods for parsing and retrieving config entries
    """
    def __init__(self, config_path):
        self.config_path = config_path
        self.ldap_uri = None
        self.ldap_base = None
        self.ldap_groups = []
        self.ldap_type = None
        self.ldap_user = None
        self.ldap_pass = None
        self.ldap_mail = 'mail' # Default value


    def load_config(self):
        """ Loads the configuration file """
        if not self.config_path:
             sys.exit('Error: Configuration file path not provided.')

        parser = configparser.ConfigParser(defaults={"mail": "mail"}) # Provide default for optional mail
        try:
            # Use encoding='utf-8' for broader compatibility
            if not parser.read(self.config_path, encoding='utf-8'):
                 sys.exit(f'Error: Could not read configuration file: {self.config_path}')
        except configparser.MissingSectionHeaderError:
             sys.exit(f'Error: Configuration file {self.config_path} is missing section headers (e.g., [ldap]).')
        except Exception as e:
             sys.exit(f'Error reading configuration file {self.config_path}: {e}')

        try:
            # LDAP Section
            if not parser.has_section('ldap'): raise configparser.NoSectionError('ldap')
            self.ldap_uri     = parser.get('ldap', 'uri')
            self.ldap_base    = parser.get('ldap', 'base')
            # Make the output ["group1","...","..."]
            self.ldap_groups  = [i.strip() for i in parser.get('ldap', 'groups').split(',') if i.strip()]
            # Use fallback=None for optional type
            self.ldap_type    = parser.get('ldap', 'type', fallback=None)
            self.ldap_user    = parser.get('ldap', 'binduser')
            self.ldap_pass    = parser.get('ldap', 'bindpass')
            # mail has a default, so get() is fine
            self.ldap_mail    = parser.get('ldap', 'mail')

            # Basic validation
            if not self.ldap_uri or not self.ldap_base or not self.ldap_groups or not self.ldap_user or not self.ldap_pass:
                 raise ValueError("Missing required LDAP configuration values (uri, base, groups, binduser, bindpass).")

        except configparser.NoSectionError as e:
            sys.exit(f'Configuration Error: Missing section [{e.section}] in {self.config_path}')
        except configparser.NoOptionError as e:
            sys.exit(f'Configuration Error: Missing option "{e.option}" in section [{e.section}] in {self.config_path}')
        except ValueError as e:
             sys.exit(f'Configuration Error: {e} in {self.config_path}')
        except Exception as e:
             sys.exit(f'Unexpected error loading configuration from {self.config_path}: {e}')

def ldap_zabbix_sync(config):
    """
    Compares LDAP and Zabbix groups and members based on config.
    Sync Zabbix with LDAP users
    """
    global lowercase # Use global lowercase flag
    
    global LDAP_API_Call

    refresh_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f">>> Script refresh time: {refresh_time}\n")

    # --- Initialize Connections ---
    ldap_conn = LDAPConn(config.ldap_uri, config.ldap_base, config.ldap_user, config.ldap_pass)
    ldap_conn.connect()

    # --- Check Configured Groups ---
    print("\n>>> Checking configured groups...")

    # Convert list to set (ldap groups and zabbix groups)
    configured_ldap_groups = set(config.ldap_groups) # Groups listing in config file {'ldapgroupname'}
    # print (f"configured_ldap_groups: {configured_ldap_groups} \n")

    # Get all ldap_member_list with {'ldap_group': ['username'],....}      
    ldap_members_list = ldap_conn.get_group_members(configured_ldap_groups)
    # print ("    Ldap_members_list",ldap_members_list, "\n")

    # --- Compare Members for Each Configured Group ---
    print("\n>>> Checking memberships for each configured group...")
    for group_name in sorted(config.ldap_groups):
        print(f"\n---------------- Group: {group_name} ------------------")

        if group_name not in ldap_members_list:
            print(f"LDAP group '{group_name}' not found or error fetching members. Skipping comparison for this group.")
            continue # Skip to next group if LDAP group not found/error
        
        # Ensure members are strings for set operations
        ldap_members = set(m.decode(LDAP_ENCODING) if isinstance(m, bytes) else m for m in ldap_members_list[group_name])
        print(f"Found {len(ldap_members)} members in LDAP group '{group_name}'.")

        # Sort as integers but print as zero-padded strings
        sorted_ids = sorted(ldap_members, key=lambda x: (len(x), x))
        max_width = max(len(id) for id in sorted_ids)

        # Print with 10 per line, aligned
        for i in range(0, len(sorted_ids), 10):
            line = sorted_ids[i:i+10]
            print(', '.join(f"{id:<{max_width}}" for id in line))

                
    print ("LDAP_API_Call: ", LDAP_API_Call)

    # Disconnect from LDAP API
    try:
        print (">>> Disconnecting from LDAP Server...")
        ldap_conn.disconnect()
        print (">>> Successfully disconnected LDAP Server.\n")
    except Exception as e:
        print (f">>> Warning: Failed to disconnect from LDAP Server: {e}")


def main():
    start_time = time.time()
    usage="""
    Usage: zabbix-ldap-sync [-l] -f <config>
       zabbix-ldap-sync -v
       zabbix-ldap-sync -h

    Options:
      -h, --help                    Display this usage info
      -v, --version                 Display version and exit
      -l, --lowercase               Create AD user names as lowercase
      -f <config>, --file <config>  Configuration file to use

    """
    args = docopt(usage, version="0.1.1")

    config = LDAPConf(args['--file'])
    config.load_config()

    # set up AD differences, if necessary
    global active_directory
    global group_filter
    global group_member_attribute
    global uid_attribute
    global lowercase
    global LDAP_API_Call
    lowercase = args['--lowercase']

    # To configure how the script builds LDAP search filters and which attributes it looks for,
    # based on the LDAP type
    if config.ldap_type == 'activedirectory':
        active_directory = "true"
        group_filter = "(&(objectClass=group)(name=%s))"
        group_member_attribute = "member"
        uid_attribute = "sAMAccountName"

    else:
        active_directory = None
        group_filter = "(&(objectClass=groupofuniquenames)(cn=%s))"
        group_member_attribute = "uniquemember"
        uid_attribute = "uid" # Define uid_attribute for non-AD

    ldap_zabbix_sync(config)
    end_time = time.time()
    duration = end_time - start_time
    print(f"Execution time: {duration:.5f} seconds")

# python convention to ensure some code run only if the script is directly and 
# import file to another script, main() will not execute
if __name__ == '__main__':
    main()

