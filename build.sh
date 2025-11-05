#!/bin/bash

INITRAMFS_DIR="initramfs"
rm -rf $INITRAMFS_DIR
mkdir -p $INITRAMFS_DIR/{bin,dev,proc,sys}
cp src/wireguard-init $INITRAMFS_DIR/init
cp wireguard.conf $INITRAMFS_DIR/
cd $INITRAMFS_DIR
find . | cpio -H newc -o | gzip > ../initramfs.cpio.gz
cd ..
