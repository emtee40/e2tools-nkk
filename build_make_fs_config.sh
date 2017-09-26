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

cd e2fsprogs
autoreconf -fsi
rm -rf BUILD
mkdir BUILD
cd BUILD
../configure -prefix="$(pwd)/INSTALL"
make libs
make install-libs

cd ..
cd ..
autoreconf -fsi
rm -rf BUILD
mkdir BUILD
cd BUILD
PKG_CONFIG_PATH="$(pwd)/../e2fsprogs/BUILD/INSTALL/lib/pkgconfig" ../configure
make make_fs_config

file make_fs_config
