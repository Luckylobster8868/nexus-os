#!/bin/bash
set -e
cd "$HOME/nexus-os"

OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.4m.fd
OVMF_VARS_SRC=/usr/share/edk2/x64/OVMF_VARS.4m.fd
OVMF_VARS_LOCAL="$HOME/nexus-os/OVMF_VARS.local.fd"
ISO_PATH="$HOME/nexus-os/nexus.iso"
NVME_IMG="$HOME/nexus-os/nvme-test.img"

# OVMF_VARS must be writable; the system copy is read-only, so keep a local copy.
if [ ! -f "$OVMF_VARS_LOCAL" ]; then
    cp "$OVMF_VARS_SRC" "$OVMF_VARS_LOCAL"
fi

# Reuse the existing 64MB NVMe backing file if present, else create it fresh.
if [ ! -f "$NVME_IMG" ]; then
    qemu-img create -f raw "$NVME_IMG" 64M
fi

qemu-system-x86_64 \
  -M q35 \
  -m 512M \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$OVMF_VARS_LOCAL" \
  -cdrom "$ISO_PATH" \
  -device nvme,drive=nvmedrive,serial=deadbeef \
  -drive if=none,id=nvmedrive,format=raw,file="$NVME_IMG" \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -serial stdio \
  -no-reboot \
  -no-shutdown \
  "$@"
