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

cd $qemu_dir
PKG_CONFIG_PATH=$source_path/build/lib/x86_64-linux-gnu/pkgconfig \
./configure --enable-drm-accel --enable-vhost-user --target-list=x86_64-softmmu
make
