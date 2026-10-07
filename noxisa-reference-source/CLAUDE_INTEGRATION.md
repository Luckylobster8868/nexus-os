# Noxisa / NexusOS Reference Integration Instructions

You are working on the EXISTING Noxisa/NexusOS operating system.

The directory:

    nexus-os/

is the PRIMARY CODEBASE.

The directory:

    noxisa-reference-source/

contains REAL SOURCE CODE from mature operating systems and
research operating systems.

The reference source is INPUT.

Noxisa is the OUTPUT.

------------------------------------------------------------
CORE RULE
------------------------------------------------------------

Do NOT implement a large subsystem from scratch when a mature
implementation already exists and can be studied/adapted.

For every missing Noxisa feature:

1. Inspect the existing Noxisa implementation first.

2. Identify the exact missing capability.

3. Search the reference-source pack for mature implementations.

4. Study the actual source code.

5. Identify:
   - algorithms
   - data structures
   - state machines
   - error handling
   - synchronization
   - locking
   - memory ownership
   - recovery behavior
   - driver logic
   - ABI conventions
   - testing strategy

6. Reuse proven implementation ideas and code where legally
   compatible.

7. Adapt the implementation to Noxisa.

8. Replace foreign operating-system assumptions with Noxisa
   interfaces.

9. Preserve Noxisa's architecture.

10. Modify the EXISTING nexus-os codebase directly.

11. Build the complete system.

12. Boot Noxisa in QEMU.

13. Run relevant regression tests.

14. Fix integration issues.

15. Only consider the feature complete after actual
    verification.

------------------------------------------------------------
NO EMPTY SCAFFOLDS
------------------------------------------------------------

Do NOT create:

- empty files
- fake modules
- placeholder functions
- TODO-only implementations
- mock drivers pretending to be real drivers
- toy networking stacks
- toy filesystems
- toy window systems
- generic dashboard implementations
- fake security mechanisms

If a subsystem is not implemented yet, either:

A. adapt a mature implementation,

or

B. implement the smallest REAL production-oriented version
   required by the architecture.

------------------------------------------------------------
Noxisa architecture is authoritative
------------------------------------------------------------

Do NOT replace Noxisa with another operating system architecture.

Preserve:

- Noxisa kernel architecture
- Noxisa syscall ABI
- Noxisa capability model
- Noxisa IPC model
- Noxisa process model
- Noxisa memory-management model
- Noxisa HAL
- Noxisa VFS
- Noxisa security model
- Noxisa driver architecture

Foreign implementations must be adapted at boundaries.

Preferred structure:

    foreign implementation
            ↓
    Noxisa adapter
            ↓
    Noxisa service/interface
            ↓
    Noxisa syscall/capability layer
            ↓
    Noxisa kernel

------------------------------------------------------------
COMPATIBILITY
------------------------------------------------------------

Compatibility is a FIRST-CLASS Noxisa feature.

Study:

- Linux
- Windows NT
- Darwin/XNU
- FreeBSD
- OpenBSD
- NetBSD
- DragonFlyBSD
- Redox
- Haiku
- ReactOS
- Wine
- Plan 9
- 9front
- GNU Hurd
- MINIX
- HelenOS
- seL4
- Theseus
- QNX-like designs
- Android/AOSP
- GrapheneOS
- NixOS/Linux userland

When implementing an interface, consider:

- POSIX compatibility
- Linux compatibility
- Windows compatibility where practical
- standard filesystem semantics
- standard socket semantics
- standard process semantics
- standard signals
- standard file descriptors
- standard errno behavior
- standard environment variables
- standard executable formats
- common userspace conventions

Compatibility must not compromise Noxisa's security model.

------------------------------------------------------------
SOURCE REUSE
------------------------------------------------------------

Before writing substantial code:

SEARCH THE REFERENCE SOURCE.

Prefer:

    mature implementation
            ↓
    understand it
            ↓
    adapt it

over:

    inventing another implementation
            ↓
    debugging it from zero

Do not copy code mechanically.

Understand:

- why the original implementation works
- assumptions it makes
- synchronization requirements
- memory ownership
- ABI expectations
- architecture-specific behavior
- failure cases
- license

Then adapt it.

------------------------------------------------------------
LICENSES
------------------------------------------------------------

Every reference project has its own license.

Never assume that all source in this directory is MIT-compatible.

Before incorporating code into Noxisa:

1. Identify the source project's license.
2. Check whether direct incorporation is compatible.
3. Preserve copyright notices and attribution.
4. Preserve required license text.
5. Preserve NOTICE files when required.
6. Do not remove license headers.
7. If direct incorporation is incompatible, use the project as
   a reference/design source rather than copying its code.

------------------------------------------------------------
MODIFICATION POLICY
------------------------------------------------------------

Modify the existing Noxisa repository.

Do not create a separate replacement implementation merely
because it is easier.

The desired workflow is:

    existing nexus-os
          +
    mature reference source
          ↓
    adapted Noxisa implementation
          ↓
    build
          ↓
    QEMU
          ↓
    regression tests

------------------------------------------------------------
VERIFICATION
------------------------------------------------------------

Every major implementation phase should finish with:

    cargo build --release

then:

    ISO build

then:

    QEMU boot

then relevant functional tests.

Existing working functionality must not regress.

If a subsystem already passes tests, preserve those tests and
extend them.

------------------------------------------------------------
IMPORTANT
------------------------------------------------------------

The reference-source directory is NOT the product.

nexus-os is the product.

Reference repositories are engineering material.

Use them aggressively, intelligently, and legally.
