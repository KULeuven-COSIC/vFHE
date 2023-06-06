# Private Verifiable Computation via Lattice-based SNARKs

This repository contains the code used for my thesis.

## Instructions

Fetch all submodules:
``` shell
git submodule update --init --recursive
```

Create Makefile:
``` shell
mkdir build && cd build && cmake ..
```

Build:
``` shell
make client
```

Run:
``` shell
./pvc/bin/client 2
```

