#ifndef PVC_PARAM
#define PVC_PARAM

/*
 * All parameters needed, see text for how they were selected
 */

#include <lwe/tests/common.hpp>

using namespace LWE;
using ftype = uint64_t;
using ntt_ind = uint16_t;

const constexpr ntt_ind NTTsize = 1 << 12;
const constexpr ftype PT_MOD = 2;

const constexpr ftype P1 = 1085276161;
const constexpr ftype P2 = 1092616193;
const constexpr ftype P3 = 1095761921;

template <ntt_ind NTTsize, ftype p>
struct F_pp {};

template <>
struct F_pp<NTTsize, P1> {
    static constexpr size_t IND = 0;

    using Fp_type = libsnark::Field<ftype, P1>;

    static LWERandomness::PseudoRandomGenerator *prg;
    static LWERandomness::DiscreteGaussian *dg;

    static void init_public_params() {
        Fp_type::prg = F_pp<NTTsize, P1>::prg;
        Fp_type::dg = F_pp<NTTsize, P1>::dg;
        Fp_type::multiplicative_generator = Fp_type(11);
        Fp_type::root_of_unity = Fp_type(41);
        Fp_type::s = 20;
    }
};

LWERandomness::PseudoRandomGenerator *F_pp<NTTsize, P1>::prg;
LWERandomness::DiscreteGaussian *F_pp<NTTsize, P1>::dg;

class P1C20 {
public:
    static constexpr const ftype p_int = P1;
    static constexpr const uint32_t query_num = 15;
    static constexpr const uint32_t tau = 5;
    static constexpr const uint32_t pt_dim = query_num * LWE::query_size;

    static constexpr const uint32_t n = 3500;
    static constexpr const double width = 4.0;
    static constexpr const uint64_t q_log = 87;
    static constexpr const uint128_t q_int = (uint128_t) 1 << q_log;
    static constexpr const uint128_t rescale_q = 389942329959458;
    using pp = F_pp<NTTsize, p_int>;
    using cp = Ring_common_pp<q_int>;
};

template <>
struct F_pp<NTTsize, P2> {
    static constexpr size_t IND = 1;

    using Fp_type = libsnark::Field<ftype, P2>;

    static LWERandomness::PseudoRandomGenerator *prg;
    static LWERandomness::DiscreteGaussian *dg;

    static void init_public_params() {
        Fp_type::prg = F_pp<NTTsize, P2>::prg;
        Fp_type::dg = F_pp<NTTsize, P2>::dg;
        Fp_type::multiplicative_generator = Fp_type(3);
        Fp_type::root_of_unity = Fp_type(7517);
        Fp_type::s = 20;
    }
};

LWERandomness::PseudoRandomGenerator *F_pp<NTTsize, P2>::prg;
LWERandomness::DiscreteGaussian *F_pp<NTTsize, P2>::dg;

class P2C20 {
public:
    static constexpr const ftype p_int = P2;
    static constexpr const uint32_t query_num = 15;
    static constexpr const uint32_t tau = 5;
    static constexpr const uint32_t pt_dim = query_num * LWE::query_size;

    static constexpr const uint32_t n = 3500;
    static constexpr const double width = 4.0;
    static constexpr const uint64_t q_log = 87;
    static constexpr const uint128_t q_int = (uint128_t) 1 << q_log;
    static constexpr const uint128_t rescale_q = 410854793832210;
    using pp = F_pp<NTTsize, p_int>;
    using cp = Ring_common_pp<q_int>;
};

template <>
struct F_pp<NTTsize, P3> {
    static constexpr size_t IND = 2;

    using Fp_type = libsnark::Field<ftype, P3>;

    static LWERandomness::PseudoRandomGenerator *prg;
    static LWERandomness::DiscreteGaussian *dg;

    static void init_public_params() {
        Fp_type::prg = F_pp<NTTsize, P3>::prg;
        Fp_type::dg = F_pp<NTTsize, P3>::dg;
        Fp_type::multiplicative_generator = Fp_type(3);
        Fp_type::root_of_unity = Fp_type(313);
        Fp_type::s = 20;
    }
};

LWERandomness::PseudoRandomGenerator *F_pp<NTTsize, P3>::prg;
LWERandomness::DiscreteGaussian *F_pp<NTTsize, P3>::dg;

class P3C20 {
public:
    static constexpr const ftype p_int = P3;
    static constexpr const uint32_t query_num = 15;
    static constexpr const uint32_t tau = 5;
    static constexpr const uint32_t pt_dim = query_num * LWE::query_size;

    static constexpr const uint32_t n = 3500;
    static constexpr const double width = 4.0;
    static constexpr const uint64_t q_log = 87;
    static constexpr const uint128_t q_int = (uint128_t) 1 << q_log;
    static constexpr const uint128_t rescale_q = 420467605951707;
    using pp = F_pp<NTTsize, p_int>;
    using cp = Ring_common_pp<q_int>;
};

LWERandomness::PseudoRandomGenerator* PRG = new LWERandomness::PseudoRandomGenerator();
std::vector<LWERandomness::DiscreteGaussian*> DGS = {
    new LWERandomness::DiscreteGaussian(P1C20::width, LWE::expand, *PRG),
    new LWERandomness::DiscreteGaussian(P2C20::width, LWE::expand, *PRG),
    new LWERandomness::DiscreteGaussian(P3C20::width, LWE::expand, *PRG)
};

#endif

