#!/usr/bin/env bash

set -euo pipefail

# Global variables
# Modules to be processed.
declare -a MODULES
# Directory where BTF files are read from.
BTF_DIR=/sys/kernel/btf
# Directory where resulting headers are placed.
OUT_DIR=$(dirname $(readlink -f "${BASH_SOURCE:-$0}"))/../src/core/probe/kernel/bpf/include/
# Process all modules.
ALL_MODULES=0

usage() {
    echo "$0 [OPTIONS] [MODULE ...]"
    echo ""
    echo "Generate split compile-able headers for vmlinux and other modules files using bpftool."
    echo ""
    echo "    MODULE: name(s) of kernel modules to process. Their btf file must exist in ${BTF_DIR} directory."
    echo "            If no module names are provided, all of the files in ${BTF_DIR} will be processed."
    echo ""
    echo "    OPTIONS:"
    echo "          -a: process all available modules."
    echo "          -d: print debug information."
    echo "          -h: show this help."
}

gen_btf() {
    local name=$1
    local out_dir=$2
    local source="${BTF_DIR}/${file}"
    local dest="${out_dir}/${file}.h"
    bpftool btf dump file ${source} format c > ${dest}
}

main() {
    if [[ $# -eq 0 ]]; then
        if [[ ${ALL_MODULES} -eq 1 ]]; then
            # Add all files except vmlinux
            MODULES=( $(ls --color=never -x -I vmlinux ${BTF_DIR}) )
        else
            usage
            exit 1
        fi
    else
        MODULES=( "$@" )
    fi
    
    # First process vmlinux
    echo "Processing vmlinux"
    local vmlinux_h="${OUT_DIR}/vmlinux.h"
    bpftool btf dump file ${BTF_DIR}/vmlinux format c > ${vmlinux_h}

    # Generate module headers and deduplicate them.
    for module in ${MODULES[@]}; do
        local module_h=${OUT_DIR}/${module}.h
        local module_h_tmp=${OUT_DIR}/${module}.h.tmp
        local module_include="__${module^^}_H__"

        echo "Processing module: ${module}"
        [ -f ${BTF_DIR}/${module} ] || \
            (echo "BTF file not found for module ${module}." 
             echo "The module might not exist or you may need to insert it.";
             exit 1)

        bpftool btf dump file ${BTF_DIR}/${module} format c > ${module_h_tmp}

        # Add initial pragmas
        cat <<EOF > ${module_h}
#ifndef ${module_include}
#define ${module_include}

#include "vmlinux.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

EOF
        # The module header contains the entire vmlinux headers plus the module-specific ones at the end.
        # Extract the difference into the deduplicated header file.
        (diff --changed-group-format='%>' --unchanged-group-format='' ${vmlinux_h} ${module_h_tmp} || true) >> ${module_h}

        # Add tail pragmas.
        cat <<EOF >> ${module_h}

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* ${module_include} */
EOF
        rm ${module_h_tmp}
    done
}

while getopts ":hda" opt; do
    case ${opt} in
        h )
            usage
            exit 0
            ;;
        d )
            set -x
            ;;
        a )
            ALL_MODULES=1
            ;;
    esac
done

shift $((OPTIND -1))
main $@
