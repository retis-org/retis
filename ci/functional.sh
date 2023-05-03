#!/bin/bash

set -e

VAGRANT_VM=${1:-f36}

vagrant ssh ${VAGRANT_VM} -- -t <<SCRIPT
    echo "Running retis functional tests"
    echo "  Kernel: \$(uname -a)"
    echo "  Repo: ${CIRRUS_REPO_FULL_NAME}"
    echo "  PR: ${CIRRUS_PR:-no}"
    echo "  Branch: ${CIRRUS_BRANCH:-no}"
    echo "  SHA: ${CIRRUS_CHANGE_IN_REPO}"

    echo "Cloning"
    [ -d retis ] && rm -rf retis

    if [ -z "$CIRRUS_PR" ]; then
      git clone --branch=$CIRRUS_BRANCH https://github.com/${CIRRUS_REPO_FULL_NAME}.git retis
      cd retis
      git reset --hard $CIRRUS_CHANGE_IN_REPO
    else
      git clone https://github.com/${CIRRUS_REPO_FULL_NAME}.git retis
      cd retis
      git fetch origin pull/$CIRRUS_PR/head:pull/$CIRRUS_PR
      git reset --hard $CIRRUS_CHANGE_IN_REPO
    fi

    cargo build
    [ -f tests/run.sh ] && tests/run.sh
SCRIPT
