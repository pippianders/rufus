#!/bin/sh
#
# Bumps the nano version according to the number of commits on this branch
#
# To have git run this script on commit, create a "pre-commit" text file in
# .git/hooks/ with the following content:
# #!/bin/sh
# source ./_pre-commit.sh

type -P sed &>/dev/null || { echo "sed command not found. Aborting." >&2; exit 1; }
type -P grep &>/dev/null || { echo "grep command not found. Aborting." >&2; exit 1; }
type -P git &>/dev/null || { echo "git command not found. Aborting." >&2; exit 1; }

VER=`git shortlog | grep -E '^[ ]+' | wc -l`
# trim spaces
TAGVER=`echo $VER`
# there may be a better way to prevent improper nano on amend. For now the detection
# of a .amend file in the current directory will do
if [ -f ./.amend ]; then
	TAGVER=`expr $TAGVER - 1`
	rm ./.amend;
fi
echo "setting nano to $TAGVER"

cat > cmd.sed <<\_EOF
s/^[ \t]*FILEVERSION[ \t]*\(.*\),\(.*\),\(.*\),.*/ FILEVERSION \1,\2,\3,@@TAGVER@@/
s/^[ \t]*PRODUCTVERSION[ \t]*\(.*\),\(.*\),\(.*\),.*/ PRODUCTVERSION \1,\2,\3,@@TAGVER@@/
s/^\([ \t]*\)VALUE[ \t]*"FileVersion",[ \t]*"\(.*\)\..*"/\1VALUE "FileVersion", "\2.@@TAGVER@@"/
s/^\([ \t]*\)VALUE[ \t]*"ProductVersion",[ \t]*"\(.*\)\..*"/\1VALUE "ProductVersion", "\2.@@TAGVER@@"/
s/^\(.*\)ufus v\(.*\)\.\(.*\)"\(.*\)/\1ufus v\2.@@TAGVER@@"\4/
s/^zadig_version=\(.*\)\..*/rufus_version=\1.@@TAGVER@@/
s/^\(.*\)"Version \(.*\) (Build \(.*\))"\(.*\)/\1"Version \2 (Build @@TAGVER@@)"\4/
_EOF

# First run sed to substitute our variable in the sed command file
sed -e "s/@@TAGVER@@/$TAGVER/g" cmd.sed > cmd.sed~
mv cmd.sed~ cmd.sed

# Run sed to update the nano version
# NB: we need to run git add else the modified files may be ignored
sed -f cmd.sed ./rufus.rc > ./rufus.rc~
mv ./rufus.rc~ ./rufus.rc
git add ./rufus.rc
sed -f cmd.sed ./rufus.h > ./rufus.h~
mv ./rufus.h~ ./rufus.h
git add ./rufus.h
#sed -f cmd.sed _bm.sh > _bm.sh~
#mv _bm.sh~ _bm.sh

# TODO?: use the following in post-commit to setup a tag every 10 commits
#if [ "${TAGVER:${#TAGVER}-1:1}" == '0' ]; then
#	echo "  commit #${TAGVER:${#TAGVER}-1:1}";
#fi