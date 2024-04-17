#!/bin/bash

help() {
	echo "Usage:"
	echo "  $0 [opts]"
	echo ""
	echo "  Generate an alphabetically ordered list of authors and update the authors file"
	echo ""
	echo "  Options:"
	echo "    -c		Checks the authors file is valid without modifying it."
	echo "    -h		Show this help."
}

while getopts "ch" opt; do
	case $opt in
	c) check_only=1 ;;
	*) help; exit ;;
	esac
done
shift $(($OPTIND - 1))

authors_file=$(git rev-parse --show-toplevel)/AUTHORS.md
authors_list="$(git log --no-merges --format='- %aN' | grep -v dependabot | sort -u)"

out=$(cat <<-EOM
# Authors

Many thanks to everyone who contributed to Retis!

In alphabetical order:
$authors_list
EOM
)

if [ "$check_only" == "1" ]; then
	authors=$(cat $authors_file)
	diff <(echo "$authors") <(echo -e "$out")
else
	echo -e "$out" > $authors_file
fi
