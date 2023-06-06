cmake_minimum_required(VERSION 3.10)
project(pvc)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if("${LATTICEZKSNARK_DIR}" STREQUAL "")
  set(
    LATTICEZKSNARK_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/depends/lattice-zksnark"
	)
else()
  set(LIBSNARK_DIR "${LIBSNARK_DIR}")
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # Common compilation flags and warning configuration
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -Wfatal-errors -pthread -maes -msse2 -msse3 -mpopcnt")
  ########### TEMPORARY ###########
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-range-loop-construct -Wno-deprecated")

  if("${MULTICORE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()

  # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "")
    set(OPT_FLAGS "-ggdb3 -O2 -march=native -mtune=native")
  endif()
endif()

set(
  CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}"
)

include_directories(.)

add_subdirectory(depends)
add_subdirectory(pvc)
