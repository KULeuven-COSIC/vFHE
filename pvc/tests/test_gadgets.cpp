#include <lwe/snark/r1cs_lattice_snark.hpp>
#include <lwe/tests/circ_lattice_params.hpp>
#include <lwe/tests/common.hpp>

#include "pvc/gadgets/tests.cpp"
#include "pvc/lattice_parameters.cpp"

using namespace libsnark;
using namespace LWE;

int main() {

    using Param = P1C20;
    using ppT = F_pp<NTTsize, P1>;
    using cpT = Ring_common_pp<Param::q_int>;

    auto prg = new LWERandomness::PseudoRandomGenerator();
    auto dg =
        new LWERandomness::DiscreteGaussian(Param::width, LWE::expand, *prg);

    public_params_init<ppT, cpT>(prg, dg);

    std::cout << "q_log = " << Param::q_log << "\n"
              << "q_rescale = " << Param::rescale_q << "\n"
              << "pt_dim = " << Param::pt_dim << "\n"
              << "n = " << Param::n << "\n"
              << "s = " << Param::width << std::endl;
    
    /*
    libff::start_profiling();
    libff::print_header("(enter) Test R1CS lattice SNARK");
    */

    //r1cs_example<libff::Fr<ppT>> example = test_vector_add_gadget<libff::Fr<ppT>>(10);
    //r1cs_example<libff::Fr<ppT>> example = test_vector_mult_gadget<libff::Fr<ppT>>(10);
    //r1cs_example<libff::Fr<ppT>> example = test_ct_add_gadget<libff::Fr<ppT>>(10);
    //r1cs_example<libff::Fr<ppT>> example = test_ct_mult_gadget<libff::Fr<ppT>>(10);
    //r1cs_example<libff::Fr<ppT>> example = test_ct_inner_product_gadget<libff::Fr<ppT>>(1 << 8, 2);
    //r1cs_example<libff::Fr<ppT>> example = test_NTT_gadget<libff::Fr<ppT>>(1 << 3);
    
    //r1cs_example<libff::Fr<ppT>> example = test_layer1_gadget<libff::Fr<ppT>>(100, 3, 1 << 12);
    //r1cs_example<libff::Fr<ppT>> example = test_layermid_ms_gadget<libff::Fr<ppT>>(3, 3, 1 << 12);
    r1cs_example<libff::Fr<ppT>> example = test_layermid_gadget<libff::Fr<ppT>>(3, 3, 3, 1 << 12);

    std::cout << "Number of inputs: " << example.constraint_system.num_inputs() << std::endl;
    std::cout << "Number of variables: " << example.constraint_system.num_variables() << std::endl;
    std::cout << "Number of constraints: " << example.constraint_system.num_constraints() << std::endl;

    /*
    const bool res = run_r1cs_lattice_snark<ppT, cpT, Param>(example);
    if (!res)
        libff::print_header("TEST FAILED");
    libff::print_header("(leave) Test R1CS lattice SNARK on vector example");
    */

    delete prg;
    delete dg;

    return 0;
}
