#!/bin/bash

# ============================================
# Script: akfinder.sh (Final Version)
# Description: Scan files for cloud provider Access Keys
# Usage: see help
# Author: kingman
# ============================================

set -euo pipefail

show_help() {
    cat << EOF
Usage: $0 -ak [-ext suffix[,suffix...]] [directory]

Parameters:
  -ak               Enable Access Key scanning mode (required)
  -ext suffix       Specify file suffixes to scan (can be used multiple times or comma-separated)
                    If -ext is not specified, default suffix list is used:
                    db,yml,yaml,config,properties,php,java,txt,xml,json,conf,cfg,ini,env
  directory         Optional, root directory to scan. If no directory is given and -ext is not used,
                    current directory is scanned. If no directory is given but -ext is used,
                    full disk scan is performed (system directories skipped)

Directories automatically skipped during full disk scan:
  /bin /boot /dev /etc /lib /lib64 /lost+found /proc /sbin /sys /tmp /run /snap

Noise reduction strategies:
  - Matching line must contain sensitive words (key, secret, access, token, etc., supports compound words like accesskey)
  - Lines containing test/placeholder keywords are excluded (test, example, dummy, etc., as whole words)
  - Key must contain both uppercase letters and digits (avoid false positives from plain words)
  - Key characters limited to letters, digits, +, /, =, - (no commas, parentheses, spaces, etc.)
  - Automatic deduplication (same key on same line of same file output only once)
EOF
}

# Parse arguments
if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

AK_FLAG=""
EXTENSIONS=()
SEARCH_PATH=""
SCAN_FULL_DISK=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -ak)
            AK_FLAG=1
            shift
            ;;
        -ext)
            if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                echo "Error: -ext requires a suffix argument"
                exit 1
            fi
            IFS=',' read -ra SUFFIX_ARRAY <<< "$2"
            for suf in "${SUFFIX_ARRAY[@]}"; do
                suf="${suf#.}"
                if [[ -n "$suf" ]]; then
                    EXTENSIONS+=("$suf")
                fi
            done
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        -*)
            echo "Error: Unknown option $1"
            show_help
            exit 1
            ;;
        *)
            if [[ -z "$SEARCH_PATH" ]]; then
                SEARCH_PATH="$1"
                shift
            else
                echo "Error: Only one directory can be specified"
                exit 1
            fi
            ;;
    esac
done

if [[ -z "$AK_FLAG" ]]; then
    echo "Error: -ak parameter is required"
    show_help
    exit 1
fi

# Determine scan path and suffix list
if [[ -z "$SEARCH_PATH" ]]; then
    if [[ ${#EXTENSIONS[@]} -eq 0 ]]; then
        SEARCH_PATH="."
        DEFAULT_SUFFIXES=(
            "db" "yml" "yaml" "config" "properties" "php" "java"
            "txt" "xml" "json" "conf" "cfg" "ini" "env"
        )
        EXTENSIONS=("${DEFAULT_SUFFIXES[@]}")
    else
        SCAN_FULL_DISK=1
        SEARCH_PATH="/"
    fi
else
    SCAN_FULL_DISK=0
    if [[ ${#EXTENSIONS[@]} -eq 0 ]]; then
        DEFAULT_SUFFIXES=(
            "db" "yml" "yaml" "config" "properties" "php" "java"
            "txt" "xml" "json" "conf" "cfg" "ini" "env"
        )
        EXTENSIONS=("${DEFAULT_SUFFIXES[@]}")
    fi
fi

if [[ ! -d "$SEARCH_PATH" ]]; then
    echo "Error: Directory '$SEARCH_PATH' does not exist"
    exit 1
fi

EXCLUDE_DIRS=(
    "/bin" "/boot" "/dev" "/etc" "/lib" "/lib64" "/lost+found"
    "/proc" "/sbin" "/sys" "/tmp" "/run" "/snap"
)

build_find_command() {
    local base_path="$1"
    local -n suffixes_ref=$2
    local find_cmd="find \"$base_path\""
    if [[ $SCAN_FULL_DISK -eq 1 ]]; then
        for excl in "${EXCLUDE_DIRS[@]}"; do
            find_cmd+=" -path \"$excl\" -prune -o"
        done
    fi
    find_cmd+=" -type f"
    if [[ ${#suffixes_ref[@]} -gt 0 ]]; then
        local name_cond=""
        for suf in "${suffixes_ref[@]}"; do
            if [[ -z "$name_cond" ]]; then
                name_cond="\\( -name \"*.$suf\""
            else
                name_cond+=" -o -name \"*.$suf\""
            fi
        done
        name_cond+=" \\)"
        find_cmd+=" $name_cond"
    fi
    find_cmd+=" -print0 2>/dev/null"
    echo "$find_cmd"
}

FIND_CMD=$(build_find_command "$SEARCH_PATH" EXTENSIONS)

if [[ $SCAN_FULL_DISK -eq 1 ]]; then
    echo "⚠️  Full disk scan enabled (skipping system directories)"
    echo "   Scanning root: $SEARCH_PATH"
    echo "   Skipped directories: ${EXCLUDE_DIRS[*]}"
    echo "   This may take a while, please be patient..."
    echo ""
fi

eval "$FIND_CMD" | while IFS= read -r -d '' file; do
    perl -ne '
        # ---------- Noise reduction configuration ----------
        # Sensitive words: match words starting with these (allowing following chars, e.g., accesskey)
        my @sensitive = qw(
            key secret access credential token password auth
            client_id client_secret private_key api_key
        );
        # Exclude words: must be whole words (exact match)
        my @exclude = qw(
            example test dummy sample demo placeholder your replace
            changeme todo fixme null none undefined
        );

        # ---------- Cloud provider regex (strict character classes, no commas, parentheses, spaces) ----------
        my @patterns = (
            ["Google Cloud",      qr/(?<![A-Za-z0-9])(GOOG[A-Za-z0-9+\/=-]{10,30})(?![A-Za-z0-9])/],
            ["Microsoft Azure",   qr/(?<![A-Za-z0-9])(AZ[A-Za-z0-9+\/=-]{34,40})(?![A-Za-z0-9])/],
            ["Tencent Cloud",     qr/(?<![A-Za-z0-9])(AKID[A-Za-z0-9+\/=-]{13,20})(?![A-Za-z0-9])/],
            ["AWS",               qr/(?<![A-Za-z0-9])(AKIA[A-Za-z0-9+\/=-]{16})(?![A-Za-z0-9])/],
            ["IBM Cloud",         qr/(?<![A-Za-z0-9])(IBM[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            ["Oracle Cloud",      qr/(?<![A-Za-z0-9])(OCID[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            # Alibaba Cloud length range 12~28 (total 16~32), supports long test keys
            ["Alibaba Cloud",     qr/(?<![A-Za-z0-9])(LTAI[A-Za-z0-9+\/=-]{12,28})(?![A-Za-z0-9])/],
            ["Huawei Cloud",      qr/(?<![A-Za-z0-9])(AK[A-Za-z0-9+\/=-]{10,62})(?![A-Za-z0-9])/],
            ["Baidu Cloud",       qr/(?<![A-Za-z0-9])(AK[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            ["JD Cloud",          qr/(?<![A-Za-z0-9])(AK[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            ["UCloud",            qr/(?<![A-Za-z0-9])(UC[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            ["QingCloud",         qr/(?<![A-Za-z0-9])(QY[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            ["Kingsoft Cloud",    qr/(?<![A-Za-z0-9])(KS3[A-Za-z0-9+\/=-]{10,40})(?![A-Za-z0-9])/],
            ["China Unicom Cloud",qr/(?<![A-Za-z0-9])(LTC[A-Za-z0-9+\/=-]{10,60})(?![A-Za-z0-9])/],
            ["China Mobile Cloud",qr/(?<![A-Za-z0-9])(YD[A-Za-z0-9+\/=-]{10,60})(?![A-Za-z0-9])/],
            ["China Telecom Cloud",qr/(?<![A-Za-z0-9])(CTC[A-Za-z0-9+\/=-]{10,60})(?![A-Za-z0-9])/],
            ["Yonyou Cloud",      qr/(?<![A-Za-z0-9])(YYT?[A-Za-z0-9+\/=-]{10,60})(?![A-Za-z0-9])/],
            ["G-Core Labs",       qr/(?<![A-Za-z0-9])(gcore[A-Za-z0-9+\/=-]{10,30})(?![A-Za-z0-9])/],
        );

        my $line_lc = lc $_;
        # Exclude word filtering (whole words)
        foreach my $ex (@exclude) {
            if ($line_lc =~ /\b$ex\b/) {
                next;
            }
        }

        # Sensitive word check (match words starting with sensitive word, allowing following characters like accesskey)
        my $has_sensitive = 0;
        foreach my $sens (@sensitive) {
            if ($line_lc =~ /\b$sens/) {
                $has_sensitive = 1;
                last;
            }
        }
        next unless $has_sensitive;

        # Match keys (with line-level deduplication)
        my %seen;
        foreach my $p (@patterns) {
            my ($name, $regex) = @$p;
            while ($_ =~ /$regex/g) {
                my $key = $1;
                # Basic filtering
                next if $key =~ /^\d+$/;              # digits only
                next if $key =~ /^(.)\1+$/;           # single repeated character
                next if $key =~ /x{4,}/i;             # 4 or more consecutive x
                next if $key =~ /^\*+$/;              # only asterisks
                next if $key !~ /[A-Z]/;              # must contain uppercase letter
                next if $key !~ /[0-9]/;              # must contain digit
                # Deduplicate (same key, same line, same file output only once)
                my $sig = "$ARGV:$.:$key";
                next if $seen{$sig}++;
                print "$ARGV:$.:$name: $key\n";
            }
        }
    ' "$file"
done
