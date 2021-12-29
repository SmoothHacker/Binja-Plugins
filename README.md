# Binja-Plugins
Collection of small scripts and plugins for Vector35's Binary Ninja

## Format String Fixer
Searches for the format strings for the `printf` function and marks them as a `const char[]` so that the string value appears in the disassembly instead of a `data_xxxx`.

## Headless BNDB Creator
Creates a bndb for file on a headless version of binary ninja

## Syscall Reporter
Gives a report detailing the addresses and type of syscalls in a binary

