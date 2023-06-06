#include <lwe/snark/r1cs_lattice_snark.hpp>
#include <lwe/tests/common.hpp>

#include <pvc/gadgets/tests.cpp>
#include <pvc/lattice_parameters.cpp>

int main() {

    using Params = P3C20;
    using ppT = F_pp<NTTsize, P3>;
    using cpT = Ring_common_pp<Params::q_int>;

    auto prg = new LWERandomness::PseudoRandomGenerator();
    auto dg = new LWERandomness::DiscreteGaussian(Params::width, LWE::expand, *prg);
    
    public_params_init<ppT, cpT>(prg, dg);

    std::cout << "q_log = " << Params::q_log << "\n"
              << "q_rescale = " << Params::rescale_q << "\n"
              << "pt_dim = " << Params::pt_dim << "\n"
              << "n = " << Params::n << "\n"
              << "s = " << Params::width << std::endl;

    libff::start_profiling();
    libff::print_header("(enter) Test R1CS lattice SNARK");
    //r1cs_example<libff::Fr<ppT>> example = test_NTT_gadget<libff::Fr<ppT>>(1 << 3);
    r1cs_example<libff::Fr<ppT>> example = generate_r1cs_example_with_field_input<libff::Fr<ppT>>(1 << 10, 100);
    std::cout << "Num_constraints: " << example.constraint_system.num_constraints() << std::endl;
    std::cout << "Num_variables: " << example.constraint_system.num_variables() << std::endl;
    std::cout << "Num_inputs: " << example.constraint_system.num_inputs() << std::endl;

    const bool res = run_r1cs_lattice_snark<ppT, cpT, Params>(example);
    if (!res)
        libff::print_header("TEST FAILED");

    libff::print_header("(leave) Test R1CS lattice SNARK");

    delete prg;
    delete dg;

    return 0;
}
