#!/bin/bash

help() {
	echo "Usage:"
	echo "  $0 [opts]"
	echo ""
	echo "  Generate an alphabetically ordered list of authors and update the authors file"
	echo ""
	echo "  Options:"
	echo "    -n		Dry run (show what would be modified)."
	echo "    -h		Show this help."
}

while getopts "hn" opt; do
	case $opt in
	n) dry_run=1 ;;
	*) help; exit ;;
	esac
done
shift $(($OPTIND - 1))

authors_file=$(git rev-parse --show-toplevel)/AUTHORS.md
authors_list="$(git log --no-merges --format='- %aN' | grep -v dependabot | sort -fu)"

out=$(cat <<-EOM
# Authors

Many thanks to everyone who contributed to Retis!

In alphabetical order:
$authors_list
EOM
)

if [ "$dry_run" == "1" ]; then
	authors=$(cat $authors_file)
	diff -u <(echo "$authors") <(echo -e "$out")
else
	echo -e "$out" > $authors_file
fi
