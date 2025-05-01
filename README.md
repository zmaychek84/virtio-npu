# virtio-npu

## Build instructions
```
./configure
./build.sh
```

## Start VM with NPU

### Build kernel image and rootfs. Then start the VM.
```
# Kernel: /tmp/bzImage
# Rootfs: /scratch/lizhi/rootfs.img

qemu-system-x86_64 -enable-kvm -object memory-backend-memfd,id=mem1,size=8G -machine q35,accel=kvm,usb=off,dump-guest-core=off,memory-backend=mem1 -smp 4,sockets=4,cores=1,threads=1 -kernel /scratch/bzImage -nographic -append "root=/dev/vda console=ttyS0" -drive file=/scratch/lizhi/rootfs.img,media=disk,cache=none,if=virtio -device virtio-accel-pci,accel-node=accel0 -cpu host
```

## Test

### Build and run simple test
```
gcc -Ivirglrenderer/src/ -Ivirglrenderer/src/drm/amdxdna/ -I/lib/modules/`uname -r`/build/include/uapi/drm/ -L/usr/lib/x86_64-linux-gnu ioctl_test.c -ldrm
```
