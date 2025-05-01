# virtio-npu

## Build instructions
```
git clone https://github.com/amd/virtio-npu.git
cd virtio-npu
git submodule update --init --recursive
./configure
./build.sh
```

#### xdna-driver submodule
Build and install amdxdna driver on host side
Build and run tests in VM
 
Please see https://github.com/amd/xdna-driver
## Start VM with NPU

### Build kernel image and rootfs. Then start the VM.
```
# Kernel: /scratch/bzImage
# Rootfs: /scratch/rootfs.img

qemu-system-x86_64 -enable-kvm -object memory-backend-memfd,id=mem1,size=8G -machine q35,accel=kvm,usb=off,dump-guest-core=off,memory-backend=mem1 -smp 4,sockets=4,cores=1,threads=1 -kernel /scratch/bzImage -nographic -append "root=/dev/vda console=ttyS0" -drive file=/scratch/rootfs.img,media=disk,cache=none,if=virtio -device virtio-accel-pci,accel-node=accel0 -cpu host
```

## Test

### Build and run simple test
```
gcc -Ivirglrenderer/src/ -Ivirglrenderer/src/drm/amdxdna/ -I/lib/modules/`uname -r`/build/include/uapi/drm/ -L/usr/lib/x86_64-linux-gnu ioctl_test.c -ldrm
```
