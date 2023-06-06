#ifndef PVC_CLIENT
#define PVC_CLIENT

#include <pvc/bgv.cpp>
#include <lwe/snark/r1cs_lattice_snark.hpp>

/*
 * Stores and executes everyting SNARK related for one field
 */
template <typename Params>
struct snarker {
    using ppT = typename Params::pp;
    using cpT = typename Params::cp;
    using F = typename ppT::Fp_type;
    
    std::vector<r1cs_lattice_snark_crs<ppT, cpT, Params>> crs;
    std::vector<r1cs_lattice_snark_verification_key<ppT, cpT, Params>> vk;
    std::vector<r1cs_lattice_snark_proof<ppT, cpT, Params>> proof;

    void generate_crs_vk(std::vector<protoboard<F>> pboards) {
        for (size_t i = 0; i < pboards.size(); ++i) {
            crs.emplace_back(r1cs_lattice_snark_crs<ppT, cpT, Params>());
            vk.emplace_back(r1cs_lattice_snark_verification_key<ppT, cpT, Params>());
            libff::print_header("R1CS lattice SNARK Generator");
            r1cs_lattice_snark_generator<ppT, cpT, Params>(pboards[i].get_constraint_system(), crs[i], vk[i]);
            printf("\n");
        }
    }
    
    void generate_proof(std::vector<protoboard<F>> pboards) {
        for (size_t i = 0; i < pboards.size(); ++i) {
            libff::print_header("R1CS lattice SNARK Prover");
            proof.emplace_back(r1cs_lattice_snark_prove<ppT, cpT, Params>(
                crs[i], pboards[i].primary_input(), pboards[i].auxiliary_input()));
            printf("\n");
        }
    }

    bool verify(std::vector<protoboard<F>> pboards) {
        bool res = true;
        for (size_t i = 0; i < pboards.size(); ++i) {
            libff::print_header("R1CS lattice SNARK Verifier");
            res &= r1cs_lattice_snark_verify<ppT, cpT>(vk[i], pboards[i].primary_input(), proof[i]);
            printf("\n");
        }
        return res;
    }
};

/*
 * Main class that executes all PVC methods
 */
template <typename... params>
class Client {
public:
    
    // Specific PVC instantiation for some homomorphic circuit
    BGVexample<params...> bgv;
    // Everything SNARK related per field
    std::tuple<snarker<params>...> snarkers;

    Client(int k) : bgv(BGVexample<params...>(2*k))
    {
        libff::start_profiling();
        init_snarker<params...>();
        libff::print_mem("after generator");
    };

    template <typename p, typename... ps>
    void init_snarker() {
        std::get<snarker<p>>(snarkers).generate_crs_vk(bgv.template get_protoboards<p, ps...>());
        if constexpr (sizeof...(ps) > 0)
            init_snarker<ps...>();
    }

    void prove() {
        bgv.calculate_boards();
        prove_snarker<params...>();
        libff::print_mem("after prover");
    }

    template <typename p, typename... ps>
    void prove_snarker() {
        std::get<snarker<p>>(snarkers).generate_proof(bgv.template get_protoboards<p, ps...>());
        if constexpr (sizeof...(ps) > 0)
            prove_snarker<ps...>();
    }

    bool verify() {
        bool res = true;
        verify_snarker<params...>(res);
        libff::print_mem("after verifier");
        return res;
    }

    template <typename p, typename... ps>
    void verify_snarker(bool& status) {
        status &= std::get<snarker<p>>(snarkers).verify(bgv.template get_protoboards<p, ps...>());
        if constexpr (sizeof...(ps) > 0)
            verify_snarker<ps...>(status);
    }

};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "provide inner product size k as argument" << std::endl;
        return -1;
    }
    
    // instantiate Client for parameters P1C20, P2C20 and P3C20, also does setup
    Client<P1C20, P2C20, P3C20> client{std::stoi(std::string(argv[1]))};
    
    // calculate and generate proofs for all circuits
    client.prove();
    
    // verify all proofs
    printf("The result of total verification is: %s\n", (client.verify() ? "PASS" : "FAIL"));

    return 0;
}

#endif

