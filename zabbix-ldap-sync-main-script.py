#!/usr/bin/env python3

"""
Purpose: The zabbix-ldap-sync script is used for syncing LDAP users with Zabbix.
Modified by: Wan Shan Jie
Last Revised: 2025-June 5 
Usage: python3 /etc/zabbix/externalscripts/zabbix-ldap-sync-main-script.py -l -f /etc/zabbix/externalscripts/zabbix-ldap.conf > /etc/zabbix/externalscripts/zabbix-ldap-sync-output.log 2>&1
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

from pyzabbix import ZabbixAPI 
from docopt import docopt
from pathlib import Path

LDAP_API_Call = 0
Zbx_API_Call =  0

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
            return 0


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


    def get_group_name(self):
        
        global LDAP_API_Call, LDAP_ENCODING

        base_str = self.base.decode(LDAP_ENCODING) if isinstance(self.base, bytes) else self.base

        # Only search the group starts with sgbdc
        group_filters = "(&(objectClass=group)(cn=sgbdc*))"
        LDAP_API_Call +=1
        try:
            results = self.conn.search_s(
                base=base_str,
                scope=ldap.SCOPE_SUBTREE,
                filterstr=group_filters,
                attrlist=['cn']
            )

            # Extract the 'cn' attribute values into a set
            group_names = set()
            for dn, attrs in results:
                if isinstance(attrs, dict) and 'cn' in attrs:
                    for cn in attrs['cn']:
                        group_names.add(cn.decode(LDAP_ENCODING) if isinstance(cn, bytes) else cn)
            
            # print ("    LDAP_API_Call", LDAP_API_Call, "in get_group_name function")
            return group_names

        except ldap.LDAPError as e:
            print(f"[ERROR] LDAP group search failed: {e}")
            return set()

class ZabbixConn(object):
    """
    Zabbix connector class

    Defines methods for managing Zabbix users and groups

    """
    def __init__(self, server, username, password):
        self.server   = server
        self.username = username
        self.password = password

    def connect(self):
        """
        Establishes a connection to the Zabbix server

        Raises:
            SystemExit

        """

        self.conn = ZabbixAPI(self.server)
        self.conn.session.verify = False


        try:
            self.conn.login(self.username, self.password)
            print(f">>> Successfully connected to Zabbix server: {self.server}")
            return 1
        except Exception as e:
            print(f'Zabbix Error: Cannot login to Zabbix server {self.server}: {e}')
            return 0


    def get_users(self):
        """
        Retrieves the existing Zabbix users

        Returns:
            A list of the existing Zabbix users

        """
        global Zbx_API_Call 

        Zbx_API_Call +=1
        result = self.conn.user.get(output='extend', selectUsrgrps= ["usrgrpid"])
        users = [
            {'userid': user['userid'], 
             "username": user['username'],
             "selectUsrgrps": [grp['usrgrpid'] for grp in user.get('usrgrps', [])]
            } for user in result
        ]
        return users

    def get_user_id(self, username):
        """
        Retrieves the userid of a specified user

        Args:
            username (str): The Zabbix username to lookup

        Returns:
            The userid of the specified user

        """
        users = self.get_users()  
        for user in users:
            if user['username'] == username:
                return user['userid']
        raise ValueError(f"User '{username}' not found")

    def get_groups(self):
        """
        Retrieves the existing Zabbix groups

        Returns:
            A dict of the existing Zabbix groups and their group ids

        """
        global Zbx_API_Call 
        Zbx_API_Call +=1

        result = self.conn.usergroup.get(output='extend')
        group = [{'name': group['name'], 'usrgrpid': group['usrgrpid']} for group in result]
        # print ("    Zbx_API_Call", Zbx_API_Call, "in get_groups function")

        return group

    def get_group_members(self, groupid):
        """
        Retrieves group members for a Zabbix group

        Args:
            groupid (int): The group id

        Returns:
            A list of the Zabbix users for the specified group id

        """
        global Zbx_API_Call 
        Zbx_API_Call +=1

        result = self.conn.user.get(output='extend',usrgrpids=groupid)
        # print ("result: ", result, "\n")
        users = [{'userid': user['userid'], 'username': user['username']} for user in result]

        # print ("    Zbx_API_Call", Zbx_API_Call, "in get_group_members function")
        return users
    
    def get_role_id(self):
        """
        Retrieves the role_id and its name

        Returns:
            A dict of the role name and roleid

        """
        global Zbx_API_Call 
        Zbx_API_Call +=1

        result = self.conn.role.get(output=["name", "roleid"])

        return result

    def create_group(self, group):
        """
        Creates a new Zabbix group

        Args:
            group (str): The Zabbix group name to create

        Returns:
            The groupid of the newly created group

        """

        global Zbx_API_Call 
        Zbx_API_Call +=1

        result = self.conn.usergroup.create(name=group,rights=[{ 'permission' : 3 , 'id' : 1 }],users_status=0)
        groupid = result['usrgrpids'].pop()

        print (f"    Created group {group} with id {groupid}. \nPlease note, the newly create user group must have proper permissions assigned and be enabled before being available for user.")
        return groupid
    
    def create_user(self, user, groupid):
        """
        Creates a new Zabbix user

        Args:
            user    (dict): A dict containing the user details
            groupid  (int): The groupid for the new user

        """
        global Zbx_API_Call 
        
        random_passwd = ''.join(random.sample(string.ascii_letters + string.digits, 32))
        # print ("default_passwd", random_passwd, "\n")
        user_defaults = { 'autologin': 0, 'lang': 'en_US', 'usrgrps': [ { 'usrgrpid': str(groupid) } ], 'passwd': random_passwd}
        # Merging data into the user dictionary
        user.update(user_defaults)

        Zbx_API_Call +=1
        result = self.conn.user.create(user)

        # print ("    Zbx_API_Call", Zbx_API_Call, "in create_user function")
        return result
    
    def create_missing_groups(self, ldap_groups):
        """
        Creates any missing LDAP groups in Zabbix

        Args:
            ldap_groups (list): A list of LDAP groups to create

        """
        for eachGroup in ldap_groups:
            try:
                print(f">>> Creating Zabbix group {eachGroup}")
                groupid = self.create_group(eachGroup)
                print(f"    Group {eachGroup} created with groupid {groupid}\n")
            except Exception as e:
                print(f"[ERROR] Failed to create group {eachGroup}: {e}")
    
    def update_media(self, user, mail):
        """
        Adds media (email) to an existing Zabbix user

        Args:
            user    (dict): A dict containing the user details

        """
        global Zbx_API_Call 

        userid = self.get_user_id(user)
        Zbx_API_Call +=1
        result = self.conn.user.update(
            userid= userid, 
            user_medias=[ 
                { 
                    'mediatypeid': '1', 'sendto': mail, 'active': '0', 'severity': '63', 'period': '1-7,00:00-24:00' 
                    } 
                ] 
        )	    
        # print ("    Zbx_API_Call", Zbx_API_Call, "in update_media function")
        return result
    
    def update_user(self, userid, updated_groups):
        global Zbx_API_Call 
        Zbx_API_Call +=1

        try:
            self.conn.user.update({
                "userid": userid,
                "usrgrps": updated_groups
            })
            # print ("    Zbx_API_Call", Zbx_API_Call, "in update_user function")
            print(f">>> Successfully updates all users' groups.")
        except Exception as e:
                print(f"    !!! Failed to update user '{userid}': {e}")
    
class ZabbixLDAPConf(object):
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
        self.zbx_server = None
        self.zbx_username = None
        self.zbx_password = None

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

            # Zabbix Section
            if not parser.has_section('zabbix'): raise configparser.NoSectionError('zabbix')
            self.zbx_server   = parser.get('zabbix', 'server')
            self.zbx_username = parser.get('zabbix', 'username')
            self.zbx_password = parser.get('zabbix', 'password')

            # Basic validation
            if not self.ldap_uri or not self.ldap_base or not self.ldap_groups or not self.ldap_user or not self.ldap_pass:
                 raise ValueError("Missing required LDAP configuration values (uri, base, groups, binduser, bindpass).")
            if not self.zbx_server or not self.zbx_username or not self.zbx_password:
                 raise ValueError("Missing required Zabbix configuration values (server, username, password).")

        except configparser.NoSectionError as e:
            sys.exit(f'Configuration Error: Missing section [{e.section}] in {self.config_path}')
        except configparser.NoOptionError as e:
            sys.exit(f'Configuration Error: Missing option "{e.option}" in section [{e.section}] in {self.config_path}')
        except ValueError as e:
             sys.exit(f'Configuration Error: {e} in {self.config_path}')
        except Exception as e:
             sys.exit(f'Unexpected error loading configuration from {self.config_path}: {e}')

# For LDAP Connection Checking in Zabbix
def write_status_to_file(ldap, zabbix):
    current_dir = Path(__file__).parent.resolve()
    status_checking = current_dir/ "zabbix-ldap-connection-status.log"
    # status_checking = "/home_ad/769194/zabbix_connection_status.log"

    with open(status_checking, "w") as f:
        f.write((f"{ldap} {zabbix}\n"))

def ldap_zabbix_sync(config):
    """
    Compares LDAP and Zabbix groups and members based on config.
    Sync Zabbix with LDAP users
    """
    global lowercase # Use global lowercase flag
    
    global LDAP_API_Call
    global Zbx_API_Call

    refresh_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f">>> Script refresh time: {refresh_time}\n")

    # --- Initialize Connections ---
    ldap_conn = LDAPConn(config.ldap_uri, config.ldap_base, config.ldap_user, config.ldap_pass)
    ldap_status = "SUCCESS" if ldap_conn.connect()==1 else "FAILED"

    zabbix_conn = ZabbixConn(config.zbx_server, config.zbx_username, config.zbx_password)
    zabbix_status = "SUCCESS" if zabbix_conn.connect()==1 else "FAILED"

    # Write both to log
    write_status_to_file(ldap_status, zabbix_status)
    if ldap_status == "FAILED" or zabbix_status == "FAILED":
        sys.exit(1)

    # Set Zabbix data (users and its groups)
    print("\n>>> Fetching initial Zabbix data...")
    zabbix_all_users = zabbix_conn.get_users() # List of Dict: [{username: userid}]
    # print (f"zabbix_all_users: {zabbix_all_users} \n")
    zabbix_all_groups = zabbix_conn.get_groups() # List of Dict: [{groupname: groupid}]
    #print (f"zabbix_all_groups: {zabbix_all_groups} \n")
    zabbix_all_role_id = zabbix_conn.get_role_id()
    #print ("zabbix_all_role_id", zabbix_all_role_id, "\n")
    print(f"    Found {len(zabbix_all_users)} users and {len(zabbix_all_groups)} groups in Zabbix. \n")

    # --- Check Configured Groups ---
    print("\n>>> Checking configured groups...")

    # Convert list to set (ldap groups and zabbix groups)
    configured_ldap_groups = set(config.ldap_groups) # Groups listing in config file {'ldapgroupname'}
    # print (f"configured_ldap_groups: {configured_ldap_groups} \n")

    zabbix_group_names = set(group["name"]for group in zabbix_all_groups) # Groups existing in zabbix {'zbxgroupname'}

    ldap_all_groups = ldap_conn.get_group_name()
    # print (f"ldap_all_groups: {len(ldap_all_groups)} \n")
    # print (f"ldap_all_groups: {ldap_all_groups} \n")

    # Checking configured ldap group exist in zabbix group or not
    missing_zabbix_groups = configured_ldap_groups - zabbix_group_names

    current_dir = Path(__file__).parent.resolve()
    if missing_zabbix_groups:
        # Check whether missing_zabbix_groups belong to existed groups in ldap, 
        # avoid creating unneccasary groups due to typo in ldap config file/ human error 
        
        valid_groups_to_create = missing_zabbix_groups & ldap_all_groups
        invalid_groups = missing_zabbix_groups - ldap_all_groups
        if valid_groups_to_create:
            print("    WARNING: The following configured groups exist in LDAP but not Zabbix:")
            for group in sorted(valid_groups_to_create):
                print(f"    - {group}")
            zabbix_conn.create_missing_groups(valid_groups_to_create)

        if invalid_groups:
            for groups in sorted(invalid_groups):
                print (f"    Warning!!! {groups} does not exists/ match with any LDAP groups in LDAP Server\n    Please check again the configuration setup in {current_dir/(config.config_path)}.\n")
    else:
        print("    -----No missing zabbix groups-----\n")

    # Updating the zabbix_all_groups if creating a new groups in zabbix
    zabbix_all_groups = zabbix_conn.get_groups() 

    # Get all ldap_member_list with {'ldap_group': ['username'],....}      
    ldap_members_list = ldap_conn.get_group_members(configured_ldap_groups)
    # print ("    Ldap_members_list",ldap_members_list, "\n")

    # Convert list of dicts to a dictionary: {name: usrgrpid}
    zabbix_group_dict = {group['name']: group['usrgrpid'] for group in zabbix_all_groups}
    # print (f"    zabbix_group_dict: {zabbix_group_dict} \n")
    
    # Retrive all users in zabbix in 6 groups & stored in zabbix_members_by_group
    zabbix_members_by_group = {}
    for group_name in sorted(config.ldap_groups):
        # ldap group exists in zabbix group
        if group_name in zabbix_group_dict:
            zabbix_group_id = zabbix_group_dict.get(group_name)
            group_users = zabbix_conn.get_group_members(zabbix_group_id)
            zabbix_members_by_group[group_name] = group_users

    # print ("    zabbix_members_list: ", zabbix_members_by_group, "\n")

    # --- Compare Members for Each Configured Group ---
    print("\n>>> Comparing memberships for each configured group...")
    for group_name in sorted(config.ldap_groups):
        print(f"\n---------------- Group: {group_name} ------------------")

        if group_name not in ldap_members_list:
            print(f"    LDAP group '{group_name}' not found or error fetching members. Skipping comparison for this group.")
            continue # Skip to next group if LDAP group not found/error
        
        # Ensure members are strings for set operations
        ldap_members = set(m.decode(LDAP_ENCODING) if isinstance(m, bytes) else m for m in ldap_members_list[group_name])
        print(f"    Found {len(ldap_members)} members in LDAP group '{group_name}'.")


        # ldap group exists in zabbix group
        if group_name in zabbix_group_dict:
            zabbix_group_id = zabbix_group_dict[group_name]
            print(f"    Checking Zabbix (Group ID: {zabbix_group_id})...")
            zabbix_members_list = zabbix_members_by_group.get(group_name, [])
            # print ("    zabbix_members_list: ", zabbix_members_list, "\n")

            zabbix_members_username = set(user['username'] for user in zabbix_members_list)
            print(f"    Found {len(zabbix_members_username)} members in Zabbix group '{group_name}'.")

            # Compare Memberships
            ldap_only = ldap_members - zabbix_members_username
            zabbix_only = zabbix_members_username - ldap_members

            # Create user since ldap members not exist in zabbix group
            if ldap_only: 
                print(">>> Members in LDAP group but NOT in Zabbix group:")
                for users in ldap_only:
                    print(f"    - {users}")
                usernames = sorted(ldap_only)
                attributes = ['sn', 'givenName', 'mail']
                ldap_get_all_attributes = ldap_conn.get_users_attributes(usernames,attributes)
                # print("\n    ldap_get_all_attributes: ", ldap_get_all_attributes)

                # Create mapping from role name to ID
                role_name_to_id = {r['name']: r['roleid'] for r in zabbix_all_role_id}
                if group_name == 'sgbdc-zabbix-prd-administrators':
                    roleid = role_name_to_id['Super admin role']
                elif group_name == 'sgbdc-zabbix-prd-operators':
                    roleid = role_name_to_id['Admin role']
                else:
                    roleid = role_name_to_id['User role']

                for user in sorted(ldap_only):
                    # Ensure user is string for dict lookup
                    existing_username = {u['username'] for u in zabbix_all_users}
                    if user not in existing_username:
                        
                        attrs = ldap_get_all_attributes.get(user, {})
                        user_str = {
                            'username': user,
                            'name': attrs.get('givenName',''),
                            'surname': attrs.get('sn',''),
                            'roleid' : roleid
                        }
                        # print("    user_str: ", user_str)
                        print (f'>>> Creating a new user {user} ....') 
                        zabbix_conn.create_user(user_str, zabbix_group_id)
                        print (f'    Successfully create user: {user} in zabbix') 

                        emailstr = attrs.get('mail', '')
                        print (f'>>> Updating user media for {user} by adding email {emailstr}') 
                        mailaddress = emailstr
                        if mailaddress:
                            zabbix_conn.update_media(user, mailaddress)
                            print (f'    Successfully update a new user media in zabbix\n') 


                    else:
                        Disable_GroupID = zabbix_group_dict['Disabled']
                        existing_userid = next((u['userid'] for u in zabbix_all_users if u['username'] == user), None)
                        if user in ldap_members:
                            # Get current group IDs
                            current_groups = []
                            for u in zabbix_all_users:
                                if existing_userid in u['userid'] :
                                    select_usrgrps = u.get('selectUsrgrps')
                                    current_groups.extend(select_usrgrps)

                            print(f"    Current groups: ", current_groups)

                            # Handle case: no groups at all
                            if not current_groups:
                                current_groups = [Disable_GroupID]
                                print(f"    No groups found. Assigning 'Disable' group only.")
                            else:
                                # If user is in 'Disable' group and another group is being added, remove 'Disable'
                                if Disable_GroupID in current_groups and zabbix_group_id != Disable_GroupID:
                                    current_groups.remove(Disable_GroupID)

                                # Add new group if it's not already present
                                if str(zabbix_group_id) not in current_groups:
                                    current_groups.append(str(zabbix_group_id))

                            # Format for update
                            new_group_list = [{"usrgrpid": gid} for gid in current_groups]
                            print("    Current_groups_new:", new_group_list, "\n")

                            # Update in Zabbix
                            zabbix_conn.update_user(existing_userid, new_group_list)
                            print (f">>> Successfully updating user {existing_userid}, adding to group {group_name}")

            else:
                print("    All LDAP members are present in the Zabbix group.\n")
            

            if zabbix_only:
                print("    Members in Zabbix group but NOT in LDAP group (would be removed/disabled by sync script):")
                # print ("Zabbix only: ", zabbix_only, "\n")
                for user in sorted(list(zabbix_only)):
                    # Ensure user is string for printing
                    user_str = user.decode(LDAP_ENCODING) if isinstance(user, bytes) else user
                    print(f"      - {user_str}") 

                # Disable the Members in Zabbix Group but not in LDAP Group (Local Auth remain unchange) 
                Disable_GroupID = zabbix_group_dict['Disabled']
                Local_Auth_GroupID = zabbix_group_dict['Local Auth']
                
                # Retrieve the list of dict from zabbix all users (filter based on the members in zbx but not ldap)
                # eg. Zabbix_all_users [{'userid': '1', 'username': 'Admin', 'selectUsrgrps': ['11', '13', '7']},...
                filtered_users = [user for user in zabbix_all_users if user['username'] in zabbix_only]
                # print ("filtered_users", filtered_users, "\n")

                # Reverse LDAP map: group name => set of usernames
                ldap_members_sets = {k: set(v) for k, v in ldap_members_list.items()}
                # print ("ldap_members_sets", ldap_members_sets, "\n")

                # Reverse map: groupid => group name
                groupid_to_name = {v: k for k, v in zabbix_group_dict.items()}
                # print ("groupid_to_name", groupid_to_name, "\n")


                print(f"\n    The output that will be reflected Zabbix interface after updated/ disabled")
                for user in filtered_users:
                    username = user['username']
                    userid = user['userid']
                    current_groups = set(user.get('selectUsrgrps', []))
                    valid_groups = set()  # to store groups we want to keep
                    
                    # Track whether user matched any LDAP group
                    matched_ldap_group = False

                    for groupid in current_groups:
                        groupname = groupid_to_name.get(groupid)

                        if groupid == Local_Auth_GroupID:
                            valid_groups.add(groupid)  # Always keep Local Auth
                        elif groupname in ldap_members_sets:
                            if username in ldap_members_sets[groupname]:
                                valid_groups.add(groupid)
                                matched_ldap_group = True  # Found a valid LDAP group
                        else:
                            valid_groups.add(groupid)

                    # If user is in NO valid LDAP group and not Local Auth, add to Disabled
                    if not matched_ldap_group:
                        valid_groups.add(Disable_GroupID)
                            
                    print(f"    username: {username:<10} valid_groups: {valid_groups}")

                    # Format for Zabbix update 
                    updated_groups = [{'usrgrpid': gid} for gid in valid_groups]
                    zabbix_conn.update_user(userid,updated_groups) 

        # To update the latest users in Zabbix once update users' group/ create new users
        zabbix_all_users = zabbix_conn.get_users()

    print ("LDAP_API_Call: ", LDAP_API_Call)
    print ("Zbx_API_Call: ",Zbx_API_Call, "\n")

    # Disconnect from LDAP API
    try:
        print (">>> Disconnecting from LDAP Server...")
        ldap_conn.disconnect()
        print (">>> Successfully disconnected LDAP Server.\n")
    except Exception as e:
        print (f">>> Warning: Failed to disconnect from LDAP Server: {e}")

    # Disconnect from Zabbix API
    try:
        print (">>> Disconnecting from Zabbix Server...")
        zabbix_conn.conn.user.logout()
        print (">>> Successfully disconnected from Zabbix Server.\n")
    except Exception as e:
        print (f">>> Warning: Failed to disconnect from Zabbix Server: {e}")

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

    config = ZabbixLDAPConf(args['--file'])
    config.load_config()

    # set up AD differences, if necessary
    global active_directory
    global group_filter
    global group_member_attribute
    global uid_attribute
    # global uid_filter # Add uid_filter
    # global sn_filter
    # global givenName_filter
    # global mail_filter
    global lowercase
    global LDAP_API_Call
    global Zbx_API_Call 
    lowercase = args['--lowercase']

    # To configure how the script builds LDAP search filters and which attributes it looks for,
    # based on the LDAP type
    if config.ldap_type == 'activedirectory':
        active_directory = "true"
        group_filter = "(&(objectClass=group)(name=%s))"
        group_member_attribute = "member"
        uid_attribute = "sAMAccountName"
        # uid_filter = "(&(objectClass=person)(sAMAccountName=%s))" # Define uid_filter for AD
        # sn_filter = "(&(objectClass=person)(sAMAccountName=%s))"
        # givenName_filter = "(&(objectClass=person)(sAMAccountName=%s))"
        # mail_filter = "(&(objectClass=person)(sAMAccountName=%s))"
    else:
        active_directory = None
        group_filter = "(&(objectClass=groupofuniquenames)(cn=%s))"
        group_member_attribute = "uniquemember"
        uid_attribute = "uid" # Define uid_attribute for non-AD
        # uid_filter = "(&(objectClass=posixAccount)(uid=%s))" # Define uid_filter for non-AD
        # sn_filter = "(&(objectClass=posixAccount)(uid=%s))"
        # givenName_filter = "(&(objectClass=posixAccount)(uid=%s))"
        # mail_filter = "(&(objectClass=posixAccount)(uid=%s))"

    ldap_zabbix_sync(config)
    end_time = time.time()
    duration = end_time - start_time
    print(f"Execution time: {duration:.5f} seconds")

# python convention to ensure some code run only if the script is directly and 
# import file to another script, main() will not execute
if __name__ == '__main__':
    main()

