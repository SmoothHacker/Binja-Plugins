# Binja-Plugins
Collection of small scripts and plugins for Vector35's Binary Ninja

## Format String Fixer
Searches for the format strings for the `printf` function and marks them as a `const char[]` so that the string value appears in the disassembly instead of a `data_xxxx`.
