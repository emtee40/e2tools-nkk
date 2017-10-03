#!/bin/sh

# Simple shell script to build
#   * e2fsprogs libs and install the package to custom path
#   * make_fs_config

# Dir structure
#   e2tools
#      BUILD
#      e2fsprogs
#         BUILD
#            INSTALL/lib/pkgconfig

ROOT_DIR="$(pwd)"

cd "$ROOT_DIR"

if [ ! -d e2fsprogs ] && [ ! -d e2fsprogs/lib ]; then
	echo "e2fsprogs seems missing!"
	exit 1
fi

case "$(uname -s)" in
	CYGWIN*)
		EXE=".exe";;
esac

cd "$ROOT_DIR/e2fsprogs"
autoreconf -fsi
rm -rf BUILD
mkdir BUILD
cd BUILD
../configure -prefix="$ROOT_DIR/e2fsprogs/BUILD/INSTALL"
if [ $? != 0 ]; then echo "e2fsprogs: configure failed!"; exit 2; fi
make libs
if [ $? != 0 ]; then echo "e2fsprogs: make libs failed!"; exit 2; fi
make install-libs
if [ $? != 0 ]; then echo "e2fsprogs: make install-libs failed!"; exit 2; fi

cd "$ROOT_DIR"
autoreconf -fsi
rm -rf BUILD
mkdir BUILD
cd BUILD
PKG_CONFIG_PATH="$ROOT_DIR/e2fsprogs/BUILD/INSTALL/lib/pkgconfig" ../configure
if [ $? != 0 ]; then echo "e2tools: configure failed!"; exit 2; fi
make
if [ $? != 0 ]; then echo "make failed!"; exit 2; fi

echo "\n\n---------- OUTPUT FILES ----------"
file e2tools$EXE
echo ""
file make_fs_config$EXE
echo ""
file sysXtract$EXE
echo ""
echo ""
