# vFHE

## Dependencies

- libprocps (or call cmake with option `-DWITH_PROCPS=OFF`)
- Boost C++ libraries (or comment out line 154-155 in `depends/lattice-zksnark/depends/libsnark/CMakeLists.txt`)

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
./vfhe/bin/client 2
```

