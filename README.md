# zasm-modules
Generating binary modules with zasm and [LIEF](https://github.com/lief-project/LIEF).

### Project
This project is currently more of a demonstration for how zasm could be used to generate binary modules,
zasm provides enough information to have imports/externals/relocations/entrypoints.

### LIEF
This project builds upon [LIEF](https://github.com/lief-project/LIEF) to generate the binary modules, the interface was built to hide this and
may or may not change in the future. LIEF can currently only generate PE files from scratch which, this depends if and when LIEF might add support for generating more binaries from scratch. LIEF is a wonderful
library and we do hope to be able to make more use of it.

### Goals
Add more support for modules like COFF and potentially be fully independent from LIEF, this is not set in stone.

### Example
See the [example here](https://github.com/ZehMatt/zasm-modules/blob/master/src/example/main.cpp)

### Compiling
This library ships with an example project and uses CMake. Following should be able to build the
project:
```
cmake . -B build
cmake --build .
```
