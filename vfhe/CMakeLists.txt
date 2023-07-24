add_library(
    vfhe
    STATIC

    gadgets/basic_gadgets.cpp
    gadgets/example_gadgets.cpp
    gadgets/pb_ciphertext.cpp

    lattice_parameters.cpp
    utils.cpp
    bgv.cpp
    
    client.cpp
)

target_link_libraries(vfhe lwe_interface)

target_include_directories(
    vfhe
    PUBLIC
    ${LATTICEZKSNARK_DIR}
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

add_executable(test_params tests/test_parameters.cpp)
target_link_libraries(test_params vfhe)

add_executable(test_gadgets tests/test_gadgets.cpp)
target_link_libraries(test_gadgets vfhe)

add_executable(client client.cpp)
target_link_libraries(client vfhe)
