#!/bin/sh
# Usage:
#    ../../move-asn1-headers.sh  subdir_name  File1.h File2.h ...
# All .h and .c files in the current directory are edited to use #include <...>
# style for the .h files given on the cmdline. The given .h files are also
# moved to ../include/<subdir_name>/ so that #include <...> will work.

set -e

base_dir="$(dirname "$0")"

include_subdir="$1"
shift

include_dir="$base_dir/include/$include_subdir"
mkdir -p "$include_dir"
echo "$PWD/*.h --> $include_dir"

collect_sed_commands() {
	while [ -n "$1" ]; do
		fname="$1"
		shift

		echo "s,^#include \"$fname\"$,#include <$include_subdir/$fname>,"
	done
}

move_headers() {
	echo mv $@ "$include_dir/"
	mv $@ "$include_dir/"
}

# Replace all `#include "foo.h"' with `#include <dir/foo.h>' locally
# - Collect sed commands to replace all header includes, for efficiency
cmds="$(mktemp)"
echo "collecting sed commands..."
collect_sed_commands $@ > "$cmds"
# - Run commands on all h and c files
echo "sed -i -f \"$cmds\" *.[hc]"
sed -i -f "$cmds" *.[hc]
rm "$cmds"

# Now move sed'ed *.h files to the proper ../include/dir
move_headers $@
