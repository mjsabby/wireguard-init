#!/bin/bash

INITRAMFS_DIR="initramfs"
rm -rf $INITRAMFS_DIR
mkdir -p $INITRAMFS_DIR/{bin,dev,proc,sys}
cp /usr/bin/busybox $INITRAMFS_DIR/bin/busybox
cp src/wireguard-init $INITRAMFS_DIR/bin/wireguard-init
python3 wg2bin.py wireguard.conf wireguard.bin
cp wireguard.bin $INITRAMFS_DIR/
cd $INITRAMFS_DIR
find . | cpio -H newc -o | gzip > ../initramfs.cpio.gz
cd ..
