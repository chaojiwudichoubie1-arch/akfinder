# akfinder
A project for seeking Accesskey 、 AccessToken on Linux


===========================================
akfinder.sh - Cloud Access Key Scanner
===========================================

DESCRIPTION
-----------
akfinder.sh scans files for Access Keys (secrets) of various cloud providers.
It supports file suffix filtering, full disk scan (skipping system directories),
and advanced noise reduction to avoid false positives.

SYNOPSIS
--------
./akfinder.sh -ak [-ext suffix[,suffix...]] [directory]

PARAMETERS
----------
-ak               Enable Access Key scanning mode (required).
-ext suffix       Specify file suffixes to scan. Can be used multiple times
                  or as a comma-separated list (e.g., -ext php,java).
                  If not given, default suffixes are:
                  db,yml,yaml,config,properties,php,java,txt,xml,json,conf,cfg,ini,env
directory         Optional root directory to scan.
                  - If no directory and no -ext: current directory is scanned.
                  - If no directory but -ext given: full disk scan (skipping system directories).
                  - If directory given: scans that directory with the specified suffixes (or defaults).

FULL DISK SCAN SKIPS
--------------------
The following directories are automatically excluded during full disk scan:
/bin /boot /dev /etc /lib /lib64 /lost+found /proc /sbin /sys /tmp /run /snap

NOISE REDUCTION STRATEGIES
--------------------------
1. Matching lines must contain sensitive words: key, secret, access, credential, token, password, auth, client_id, client_secret, private_key, api_key.
2. Lines containing exclude words (example, test, dummy, sample, demo, placeholder, your, replace, changeme, todo, fixme, null, none, undefined) are skipped.
3. Keys must contain both uppercase letters and digits (prevents plain words like "AKTIESELSKAB").
4. Key characters restricted to letters, digits, +, /, =, - (no commas, parentheses, spaces).
5. Automatic deduplication: same key on same line of same file is printed only once.

SUPPORTED CLOUD PROVIDERS
-------------------------
- Google Cloud (GOOG...)
- Microsoft Azure (AZ...)
- Tencent Cloud (AKID...)
- AWS (AKIA...)
- IBM Cloud (IBM...)
- Oracle Cloud (OCID...)
- Alibaba Cloud (LTAI...)
- Huawei Cloud (AK...)
- Baidu Cloud (AK...)
- JD Cloud (AK...)
- UCloud (UC...)
- QingCloud (QY...)
- Kingsoft Cloud (KS3...)
- China Unicom Cloud (LTC...)
- China Mobile Cloud (YD...)
- China Telecom Cloud (CTC...)
- Yonyou Cloud (YY or YYT...)
- G-Core Labs (gcore...)

EXAMPLES
--------
1. Scan current directory with default suffixes:
   ./akfinder.sh -ak

2. Scan specific directory with default suffixes:
   ./akfinder.sh -ak /home/user/project

3. Scan all .php files on full disk (skip system dirs):
   sudo ./akfinder.sh -ak -ext php

4. Scan .yml and .json files in /etc (no full disk skip):
   ./akfinder.sh -ak -ext yml,json /etc

5. Scan using multiple -ext options:
   ./akfinder.sh -ak -ext php -ext java /var/www

OUTPUT FORMAT
-------------
filename:line_number:cloud_provider: access_key_value

Example:
   /home/user/config.yml:42:AWS: AKIAIOSFODNN7EXAMPLE

NOTES
-----
- Full disk scan may take a long time; use -ext to narrow scope.
- For best performance, avoid scanning binary directories (automatically skipped).
- The script uses Perl for pattern matching; ensure Perl is installed.
- Use sudo when scanning directories that require elevated privileges.

EXIT CODES
----------
0 - Normal execution (even if no keys found)
1 - Invalid parameters or directory does not exist

AUTHOR
------
kingman

VERSION
-------
0.1
