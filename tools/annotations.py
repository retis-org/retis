#!/usr/bin/python3

import os
import sys
import clang.cindex

def extract_annotated_types(file_path, annotation, clang_args):
    index = clang.cindex.Index.create()
    translation_unit = index.parse(file_path, args=clang_args)
    annotated = []

    def find_annotations(node, file_name):
        if node.location.file and node.location.file.name == file_name and node.kind in (
            clang.cindex.CursorKind.TYPEDEF_DECL,
            clang.cindex.CursorKind.STRUCT_DECL,
            clang.cindex.CursorKind.UNION_DECL,
            clang.cindex.CursorKind.ENUM_DECL,
            clang.cindex.CursorKind.VAR_DECL,
        ):
            for child in node.get_children():
                if child.kind == clang.cindex.CursorKind.ANNOTATE_ATTR and annotation in child.displayname:
                    annotated.append(node.spelling or node.displayname)
                    break

        # Recursively find annotations in child nodes
        for child in node.get_children():
            find_annotations(child, file_name)

    find_annotations(translation_unit.cursor, file_path)
    return annotated

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <header_file> <annotation> [<clang_args> ...]")
        sys.exit(1)

    header_file = sys.argv[1]
    if not os.path.isfile(header_file):
        print(f"Error: {header_file} does not exist.")
        sys.exit(2)

    annotation = sys.argv[2]
    clang_args = sys.argv[3:]

    annotated = extract_annotated_types(header_file, annotation, clang_args)

    print(" ".join(str(annotation) for annotation in annotated))
