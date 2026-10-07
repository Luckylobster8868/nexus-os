# Noxisa Reference Source Pack

This directory contains real source code from mature operating
systems, kernels, runtimes, compatibility layers, filesystems,
networking systems, graphical systems, and research operating
systems.

The purpose is NOT to create a Frankenstein operating system.

The purpose is to give Noxisa development agents real,
battle-tested implementations to study and adapt.

Primary project:

    nexus-os

Reference source:

    noxisa-reference-source

Architecture:

    Reference implementation
            ↓
    Study implementation
            ↓
    Identify reusable algorithms/data structures/code
            ↓
    Noxisa adaptation
            ↓
    Noxisa interfaces
            ↓
    Noxisa kernel/services/userspace

Noxisa's architecture remains authoritative.

Do not blindly copy foreign operating-system assumptions.

Important areas include:

- memory management
- paging
- allocators
- process management
- scheduling
- IPC
- capabilities
- syscalls
- VFS
- filesystems
- block devices
- PCI
- NVMe
- networking
- TCP/IP
- sockets
- graphics
- window systems
- input
- audio
- device drivers
- userspace
- libc
- POSIX compatibility
- package management
- security
- sandboxing
- isolation
- boot
- firmware
- power management
- debugging
- testing
- observability

Noxisa should reuse mature engineering wherever practical.

However, every imported component must respect its original
license and attribution requirements.
