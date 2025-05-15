#!/bin/sh

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025, Advanced Micro Devices, Inc.
#

source_path=$(cd "$(dirname -- "$0")"; pwd)

qemu_dir="$source_path/qemu"
virgl_dir="$source_path/virglrenderer"

cd $virgl_dir
meson setup -D drm-renderers=amdxdna --prefix $source_path/build build
cd build
ninja install

pkgconf_dir=`find $source_path/build | grep pkgconfig$`
cd $qemu_dir
PKG_CONFIG_PATH=$pkgconf_dir			\
./configure --enable-drm-accel --enable-vhost-user --target-list=x86_64-softmmu
make
