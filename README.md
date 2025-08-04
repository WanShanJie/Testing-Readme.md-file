# Retrieve LDAP Member List - GID

This Python script retrieves users from LDAP groups and displays them, useful for syncing or auditing Zabbix users with LDAP Active Directory.

----------------------------------------------------------------

## Purpose

- Connect to an LDAP/AD server using credentials
- Fetch LDAP group members
- Compare and display usernames-gid in each group
- Save results to log for reference

----------------------------------------------------------------

## 🧰 Prerequisites

This script requires **Python 3** and several Python libraries that are not included by default.

----------------------------------------------------------------

## ⚙️ 1. Setup Environment

### Step 1: Install Python 3 and pip (if not installed, go to official Python website to get it)

```bash
python --version
python -m pip install --upgrade pip
pip --version
```

### Step 2: Install Required Python Libraries

```bash
pip install python-ldap
pip install docopt
pip list
```

### Step 3: Run the Script

python3 <script.py> -l -f <zabbix.conf>

```bash
python3 ldap-member-list-script.py -l -f zabbix-ldap.conf
```
🔸 The -l flag is used to list LDAP members
🔸 The -f flag specifies the configuration file

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
----------------------------------------------------------------

## Example Output

```bash
>>> Successfully connected to LDAP server: ldaps://your-ad-server.example.com:636

>>> Checking configured groups...

>>> Checking memberships for each configured group...

---------------- Group: App-Admin-Group ------------------
Found 3 members in LDAP group 'App-Admin-Group'.
123456, 789018, 178200

---------------- Group: App-User-Group ------------------
Found 3 members in LDAP group 'App-User-Group'.
123456, 789018, 178200
---------------- Group: DB-Access-Group ------------------
Found 3 members in LDAP group 'DB-Access-Group'.
123456, 789018, 178200
```




