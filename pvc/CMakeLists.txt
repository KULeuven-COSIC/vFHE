add_library(
    pvc
    STATIC

    gadgets/gadgets.cpp
    gadgets/example_gadgets.cpp
    gadgets/pb_ciphertext.cpp

    lattice_parameters.cpp
    utils.cpp
    bgv.cpp
    
    client.cpp
)

target_link_libraries(pvc lwe_interface)

target_include_directories(
    pvc
    PUBLIC
    ${LATTICEZKSNARK_DIR}
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

add_executable(test_params tests/test_parameters.cpp)
target_link_libraries(test_params pvc)

add_executable(test_gadgets tests/test_gadgets.cpp)
target_link_libraries(test_gadgets pvc)

add_executable(client client.cpp)
target_link_libraries(client pvc)
