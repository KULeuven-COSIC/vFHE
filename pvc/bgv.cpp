#ifndef PVC_BGV
#define PVC_BGV

#include <pvc/utils.cpp>
#include <pvc/gadgets/gadgets.cpp>
#include <pvc/lattice_parameters.cpp>

/*
 * Represents the first layer in a specific field
 */
template <typename F>
struct layer1 {
    protoboard<F> pboard = protoboard<F>();
    NTT_ct_inner_product_gadget<F> gadget;
    std::vector<pb_ciphertext<F>> in_left, in_right;
    pb_ciphertext<F> output;

    layer1() : gadget(pboard) {}
    
    // BGV elements are indistinguishable from random elements in R_Q
    // therefore we can test on random inputs
    void init_random_inputs() {
        for (size_t i = 0; i < in_left.size(); ++i) {
            for (size_t j = 0; j < in_left.front().size(); ++j) {
                for (size_t k = 0; k < NTTsize; ++k) {
                    pboard.val(in_left[i][j][k]) = F::random_element();
                    pboard.val(in_right[i][j][k]) = F::random_element();
                }
            }
        }
    }
};

/*
 * Base class for the second layer in a specific field
 */
template <typename F>
struct layer2_proto {
    protoboard<F> pboard = protoboard<F>();
    std::vector<pb_variable_array<F>> c2, rlk0, rlk1;
    pb_ciphertext<F> input, output;

    // Init inputs that come from first layer in same field
    void get_same_field_inputs(layer1<F>& gb1) {
        for (size_t i = 0; i < input.size()-1; ++i) {
            for (size_t j = 0; j < NTTsize; ++j)
                pboard.val(input[i][j]) = gb1.pboard.val(gb1.output[i][j]).value;
        }
        // rlks should also be indistinguishable from random elements in R_Q
        // therefore we can test on random rlks
        for (size_t i = 0; i < rlk0.size(); ++i) {
            for (size_t j = 0; j < NTTsize; ++j) {
                pboard.val(rlk0[i][j]) = F::random_element();
                pboard.val(rlk1[i][j]) = F::random_element();
            }
        }
    }

    // Fill in one element of c2 from layer one in field Fpp1
    template <typename Fpp1>
    void drop_last_input_elt(layer1<typename Fpp1::Fp_type>& gb1) {
        for (size_t j = 0; j < NTTsize; ++j)
            pboard.val(c2[Fpp1::IND][j]) = gb1.pboard.val(gb1.output[gb1.output.size()-1][j]).value;
    }
};

/*
 * Represents second layer for fields that are removed by modswitch
 */
template <typename F>
struct layer2_ms : layer2_proto<F> {
    relinearize_gadget<F> gadget;

    layer2_ms() : gadget(this->pboard) {}
};

/*
 * Represents second layer for fields that remain after modswitch
 */
template <typename F>
struct layer2 : layer2_proto<F> {
    layer2_gadget<F> gadget;
    pb_ciphertext<F> to_remove;

    layer2() : gadget(this->pboard) {}

    // Inits extra input for modswitch that comes from layer2_ms'
    template <typename Ffrom>
    void init_to_remove_from(layer2_ms<Ffrom>& gbfrom) {
        for (size_t i = 0; i < to_remove.size(); ++i) {
            for (size_t j = 0; j < NTTsize; ++j) {
                this->pboard.val(to_remove[i][j]) = gbfrom.pboard.val(gbfrom.output[i][j]).value;
            }
        }
    }
};

/*
 * Represents an instantiation of the PVC construction for
 * the specific homomorphic circuit that was used as POC
 */
template <typename... params>
struct BGVexample {
    
    static constexpr size_t input_deg = 2;
    static constexpr size_t output_deg = 2*input_deg-1;
    static constexpr size_t modswitch_remove = 1; // how many fields the modswitch removes
    static constexpr ftype prime_to_remove = last_from_pack<params...>::type::p_int; // modulus of that field
    static constexpr size_t rns_size = sizeof...(params); // total amount of fields
    const size_t input_size;
    
    // Circuits for layer1 per field
    std::tuple<layer1<typename params::pp::Fp_type>...> layer1_boards;
    // Circuits for layer2_ms for field that will be removed
    typename last_from_pack<layer2_ms<typename params::pp::Fp_type>...>::type layer_int_ks_board;
    // Circuits for layer2 per remaining field
    tuple_type_exceptlast<layer2<typename params::pp::Fp_type>...> layer2_boards;

    BGVexample(const size_t input_size) : input_size(input_size)
    {
        assert(input_size % 2 == 0); // inputs belong to one of two equally long vectors
        init<params...>();
    }

    // Main init routine
    template <typename p, typename... ps>
    void init() {
        using F = typename p::pp::Fp_type;
        init_param<p>();
        init_layer1<p>();
        if constexpr (sizeof...(ps) >= modswitch_remove) {
            init_layer2<p, layer2<F>>(std::get<layer2<F>>(layer2_boards));
        } else
            init_layer2<p, layer2_ms<F>>(layer_int_ks_board);
        if constexpr (sizeof...(ps) > 0)
            init<ps...>();
    }
    
    // Inits RNGs and sets field specific parameters
    template <typename p>
    void init_param() {
        using Fpp = typename p::pp;
        using ring_pp = typename p::cp;

        Fpp::prg = PRG;
        Fpp::dg = DGS[p::pp::IND];
        Fpp::init_public_params();
        ring_pp::prg = PRG;
        ring_pp::dg = DGS[p::pp::IND];
        ring_pp::init_public_params();
    }
    
    // Generate constraints of circuit in layer1 in specific field
    template <typename p>
    void init_layer1() {
        using F = typename p::pp::Fp_type;
        auto& gb = std::get<layer1<F>>(layer1_boards);
        auto& pb = gb.pboard;
        gb.in_left = std::vector<pb_ciphertext<F>>(input_size/2);
        gb.in_right = std::vector<pb_ciphertext<F>>(input_size/2);
        
        for (size_t i = 0; i < input_size/2; ++i) {
            gb.in_left[i].allocate(pb, input_deg, NTTsize);
            gb.in_right[i].allocate(pb, input_deg, NTTsize);
        }
        gb.output.allocate(pb, output_deg, NTTsize);
        pb.set_input_sizes((input_size*input_deg + output_deg)*NTTsize);

        gb.gadget.initialize(gb.in_left, gb.in_right, gb.output);
        gb.gadget.generate_r1cs_constraints();
    }

    // Generate constraints of circuit in layer2 in specific field
    // can also be in field that will be removed by modswitched
    template <typename p, typename int_layer>
    void init_layer2(int_layer& gb) {
        using F = typename p::pp::Fp_type;
        constexpr bool ks_and_ms = std::is_same<int_layer, layer2<F>>::value;

        auto& pb = gb.pboard;
        gb.c2 = std::vector<pb_variable_array<F>>(rns_size);
        gb.rlk0 = std::vector<pb_variable_array<F>>(rns_size);
        gb.rlk1 = std::vector<pb_variable_array<F>>(rns_size);
        
        for (size_t i = 0; i < rns_size; ++i) {
            gb.c2[i].allocate(pb, NTTsize);
            gb.rlk0[i].allocate(pb, NTTsize);
            gb.rlk1[i].allocate(pb, NTTsize);
        }
        gb.input.allocate(pb, input_deg, NTTsize);
        gb.output.allocate(pb, output_deg, NTTsize);
        if constexpr (ks_and_ms)
            gb.to_remove.allocate(pb, input_deg, NTTsize);
        pb.set_input_sizes((ks_and_ms*output_deg + 2*input_deg + 3*rns_size)*NTTsize);
    
        if constexpr (ks_and_ms)
            gb.gadget.initialize(
                gb.input, gb.c2, gb.rlk0, gb.rlk1, gb.to_remove, (F) PT_MOD, (F) prime_to_remove, gb.output);
        else
            gb.gadget.initialize(
                gb.input, gb.c2, gb.rlk0, gb.rlk1, gb.output, (F) PT_MOD);
        gb.gadget.generate_r1cs_constraints();
    }

    // Calculate the circuits in layer1
    template <typename p, typename... ps>
    void calculate_layer1_boards() {
        using Fpp = typename p::pp;
        using F = typename Fpp::Fp_type;
        auto& gb = std::get<layer1<F>>(layer1_boards);
        
        gb.init_random_inputs();
        gb.gadget.generate_r1cs_witness();

        if constexpr (sizeof...(ps) > 0)
            calculate_layer1_boards<ps...>();
    }

    // Spread c2 output of layer 1 to all fields in layer2,
    // outer loop is over layer1, inner loop is over layer2,
    // calculate layer2_ms circuit
    template <typename p, typename... ps>
    void spread_c2_to_l2_boards() {
        using Fppfrom = typename p::pp;
        auto& gb1 = std::get<layer1<typename Fppfrom::Fp_type>>(layer1_boards);
        spread_c2_to_l2_boards_helper<Fppfrom, params...>(gb1);
        if constexpr (sizeof...(ps) > 0) {
            auto& gb2 = std::get<layer2<typename Fppfrom::Fp_type>>(layer2_boards);
            gb2.get_same_field_inputs(gb1);
            spread_c2_to_l2_boards<ps...>();
        } else {
            layer2_ms<typename Fppfrom::Fp_type>& gb2 = layer_int_ks_board;
            gb2.get_same_field_inputs(gb1);
            gb2.gadget.generate_r1cs_witness();
        }
    }
    template<typename Fppfrom, typename p, typename... ps>
    void spread_c2_to_l2_boards_helper(layer1<typename Fppfrom::Fp_type>& gbfrom) {
        if constexpr (sizeof...(ps) > 0) {
            auto& gbto = std::get<layer2<typename p::pp::Fp_type>>(layer2_boards);
            gbto.template drop_last_input_elt<Fppfrom>(gbfrom);
            spread_c2_to_l2_boards_helper<Fppfrom, ps...>(gbfrom);
        } else {
            auto& gbto = layer_int_ks_board;
            gbto.template drop_last_input_elt<Fppfrom>(gbfrom);
        }
    }
    
    // Calculate the circuits in layer2 that are not removed by modswitch
    template <typename p, typename... ps>
    void calculate_layer2_boards() {
        using Fpp = typename p::pp;
        using F = typename Fpp::Fp_type;
        auto& l_int = std::get<layer2<F>>(layer2_boards);

        l_int.init_to_remove_from(layer_int_ks_board);
        l_int.gadget.generate_r1cs_witness();
        
        if constexpr (sizeof...(ps) > modswitch_remove)
            calculate_layer2_boards<ps...>();
    }

    // Main routine that calculates all circuits
    void calculate_boards() {
        calculate_layer1_boards<params...>();
        spread_c2_to_l2_boards<params...>();
        calculate_layer2_boards<params...>();
    }

    // Main routine that retrieves circuits for every layer for a specific field
    template <typename p, typename... ps>
    std::vector<protoboard<typename p::pp::Fp_type>> get_protoboards() {
        if constexpr (sizeof...(ps) >= modswitch_remove)
            return std::vector<protoboard<typename p::pp::Fp_type>>{
                get_protoboard1<p>(), get_protoboard2<p>()};
        else
            return std::vector<protoboard<typename p::pp::Fp_type>>{
                get_protoboard1<p>(), get_protoboard_int_ks<p>()};
    }
    template <typename p>
    protoboard<typename p::pp::Fp_type>& get_protoboard1() {
        return std::get<layer1<typename p::pp::Fp_type>>(layer1_boards).pboard;
    }
    template <typename p>
    protoboard<typename p::pp::Fp_type>& get_protoboard2() {
        return std::get<layer2<typename p::pp::Fp_type>>(layer2_boards).pboard;
    }
    template <typename p>
    protoboard<typename p::pp::Fp_type>& get_protoboard_int_ks() {
        return layer_int_ks_board.pboard;
    }
};

#endif
