#!/bin/bash

set -e

dryrun="--dry-run"
name="sa-sawp"
email="sa-sawp@cyber.gc.ca"
mailmap=
mapfile=
ref="master"

function help() {
read -r -d '' HELP << EOM
Usage:
  $0 [options] [--] <comma-seperated mailmap>

Validate and rewrite author history.

Options:
  -m        use mailmap file for replacements
  -n        default name to use in replacements
  -e        default email to use in replacements
  -r        git ref
  --replace rewrite git history for the specified ref
  -h        help
EOM
    echo "$HELP"
}

options=$(getopt -o hn:e:m:r: --long replace -- "$@")
[ $? -eq 0 ] || {
    echo "Invalid arguments"
    help
    exit 1
}
eval set -- "$options"
while true; do
    case "$1" in
    -h)
        help
        exit 0
        ;;
    -n)
        shift;
        name=$1
        ;;
    -e)
        shift;
        email=$1
        ;;
    -m)
        shift;
        mapfile=$1
        ;;
    -r)
        shift;
        ref=$1
        ;;
    --replace)
        dryrun=
        ;;
    --)
        shift
        # process and trim comma seperated values
        mailmap=$(echo "$@" | tr ',' '\n' | awk '{$1=$1};1')
        break
        ;;
    esac
    shift
done

# show all contributors
function contributors() {
    git log --pretty="%an <%ae>%n%cn <%ce>" $ref | sort | uniq
}

# show contributors not in .contributors
function diff_contributors() {
    # sorted order is different on centos and ubuntu
    tmp="/tmp/.contributors.tmp"
    cat .contributors | sort > $tmp
    contributors | comm -23 - $tmp
    rm $tmp
}

# fails if a contributor is not in the approved list
function validate_contributors() {
    # return status
    local ret=1

    # show lines unique to the git log (not in .contributors)
    local result=$(diff_contributors)

    if test -z "$result"; then
        echo "Contributors on $ref"
        echo "=========================================="
        contributors
        echo
        ret=0
    else
        echo "Not in contributors list on $ref"
        echo "=========================================="
        echo -e "$result"
        echo
    fi

    return $ret
}

# uses default author for unapproved contributors
function mailmap() {
    if [ -n "$mapfile" ]; then
        cat "$mapfile"
    fi
    if [ -n "$mailmap" ]; then
        echo -e "$mailmap"
    fi
    if [[ -z "$mapfile" && -z "$mailmap" ]]; then
        diff_contributors | xargs -L1 echo "$name <$email>"
    fi
}

# exit with the return value of this command
validate_contributors || :

echo "Changes"
echo "======="
mailmap $name $email > .mailmap
cat .mailmap
echo

echo "Git filter-repo"
echo "==============="
git filter-repo $dryrun --force --use-mailmap --refs $ref
rm .mailmap
echo

# show the results of running the filter-repo command
validate_contributors
