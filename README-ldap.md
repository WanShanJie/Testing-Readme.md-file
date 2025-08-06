# LDAP Related Scripts
1. zabbix-ldap-sync-main-script.py
2. ldap-member-list-script-gid.py
3. ldap-member-list-script.py

#### scripts can be found in the production server, sgspizbxl01a
#### path: /etc/zabbix/externalscripts
----------------------------------------------------------------

## Purpose

1. Use to sync LDAP members with Zabbix users based on the groups config in zabbix-ldap.conf
2. Display the LDAP members of the groups config in zabbix-ldap.conf in GID
3. Display the LDAP members of the groups config in zabbix-ldap.conf in Username - GID 
----------------------------------------------------------------

## Prerequisites

This script requires **Python 3** and several Python libraries.

----------------------------------------------------------------

## 1. Setup Environment

### Step 1: Install Python 3 and pip (if not installed, go to Software Center get it)

* Checking the existance of python and pip 
```bash
python --version
pip --version
```

### Step 2: Install Required Python Libraries

```bash
pip install python-ldap
pip install docopt
pip list
```

### Step 3: Run the Script
1. python3 <path/script.py> -l -f <path/zabbix.conf> > <path/output.log> 2>&1
2. python3 <path/script.py> -l -f <path/zabbix.conf>

🔸 The -l flag is used to list LDAP members
🔸 The -f flag specifies the configuration file

First Script
```bash
python3 /etc/zabbix/externalscripts/zabbix-ldap-sync-main-script.py -l -f /etc/zabbix/externalscripts/zabbix-ldap.conf > /etc/zabbix/externalscripts/zabbix-ldap-sync-output.log 2>&1
```

Second Script
```bash
python3 /etc/zabbix/externalscripts/ldap-member-list-script-gid.py -l -f /etc/zabbix/externalscripts/zabbix-ldap.conf
```

Third Script
```bash
python3 /etc/zabbix/externalscripts/ldap-member-list-script.py -l -f /etc/zabbix/externalscripts/zabbix-ldap.conf
```

----------------------------------------------------------------

## 🧱 2. Common System-Level Dependencies

If you are on RHEL / CentOS / Oracle Linux / Fedora, you might need additional system libraries.

### Python Development Headers (for compiling C extensions)

```bash
sudo yum install -y python3.9-devel
```

### LDAP Libraries (needed by python-ldap)
```bash
sudo yum install -y openldap-devel
```

### GNU Compiler Collection (GCC) is missing
```bash
sudo yum install gcc python3-devel
```
----------------------------------------------------------------

## Example Output (First Script)

```bash
>>> Script refresh time: 2025-08-04 20:45:04

>>> Successfully connected to LDAP server: ldaps://adgtm.seagate.com:636/
>>> Successfully connected to Zabbix server: https://zabgate.sing.seagate.com/

>>> Fetching initial Zabbix data...
    Found 761 users and 29 groups in Zabbix. 


>>> Checking configured groups...
    -----No missing zabbix groups-----


>>> Comparing memberships for each configured group...

---------------- Group: sgbdc-zabbix-prd-administrators ------------------
    Found 13 members in LDAP group 'sgbdc-zabbix-prd-administrators'.
    Checking Zabbix (Group ID: 21)...
    Found 13 members in Zabbix group 'sgbdc-zabbix-prd-administrators'.
    All LDAP members are present in the Zabbix group.


---------------- Group: sgbdc-zabbix-prd-gfo ------------------
    Found 26 members in LDAP group 'sgbdc-zabbix-prd-gfo'.
    Checking Zabbix (Group ID: 30)...
    Found 26 members in Zabbix group 'sgbdc-zabbix-prd-gfo'.
    All LDAP members are present in the Zabbix group.


---------------- Group: sgbdc-zabbix-prd-operators ------------------
    Found 48 members in LDAP group 'sgbdc-zabbix-prd-operators'.
    Checking Zabbix (Group ID: 31)...
    Found 48 members in Zabbix group 'sgbdc-zabbix-prd-operators'.
    All LDAP members are present in the Zabbix group.


---------------- Group: sgbdc-zabbix-prd-sysadmin-dba ------------------
    Found 48 members in LDAP group 'sgbdc-zabbix-prd-sysadmin-dba'.
    Checking Zabbix (Group ID: 32)...
    Found 48 members in Zabbix group 'sgbdc-zabbix-prd-sysadmin-dba'.
    All LDAP members are present in the Zabbix group.


---------------- Group: sgbdc-zabbix-prd-users ------------------
    Found 404 members in LDAP group 'sgbdc-zabbix-prd-users'.
    Checking Zabbix (Group ID: 35)...
    Found 404 members in Zabbix group 'sgbdc-zabbix-prd-users'.
    All LDAP members are present in the Zabbix group.


---------------- Group: sgbdc-zabbix-prd-webadmin ------------------
    Found 1 members in LDAP group 'sgbdc-zabbix-prd-webadmin'.
    Checking Zabbix (Group ID: 33)...
    Found 1 members in Zabbix group 'sgbdc-zabbix-prd-webadmin'.
    All LDAP members are present in the Zabbix group.

LDAP_API_Call:  3
Zbx_API_Call:  16 

>>> Disconnecting from LDAP Server...
>>> Successfully disconnected LDAP Server.

>>> Disconnecting from Zabbix Server...
>>> Successfully disconnected from Zabbix Server.

Execution time: 0.99019 seconds
```


## Example Output (Second Script)

```bash
>>> Successfully connected to LDAP server: ldaps://your-ad-server.example.com:636

>>> Checking configured groups...

>>> Checking memberships for each configured group...

---------------- Group: App-Admin-Group ------------------
Found 4 members in LDAP group 'App-Admin-Group'.
113451, 123456, 234567, 345678

---------------- Group: App-User-Group ------------------
Found 4 members in LDAP group 'App-User-Group'.
113451, 123456, 234567, 345678


---------------- Group: DB-Access-Group ------------------
Found 4 members in LDAP group 'DB-Access-Group'.
113451, 123456, 234567, 345678

```

## Example Output (Third Scripts)
```bash
>>> Successfully connected to LDAP server: ldaps://your-ad-server.example.com:636

>>> Checking configured groups...

>>> Checking memberships for each configured group...

---------------- Group: App-Admin-Group ------------------
Found 4 members in LDAP group 'App-Admin-Group'.
AB-100234, ABC-100567, ABCD-219874, ABCDE453321

---------------- Group: App-User-Group ------------------
Found 4 members in LDAP group 'App-User-Group'.
AB-100234, ABC-100567, ABCD-219874, ABCDE453321


---------------- Group: DB-Access-Group ------------------
Found 4 members in LDAP group 'DB-Access-Group'.
AB-100234, ABC-100567, ABCD-219874, ABCDE453321

```


