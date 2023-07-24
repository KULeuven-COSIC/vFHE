#ifndef PVC_BGV
#define PVC_BGV

#include <vfhe/utils.cpp>
#include <vfhe/gadgets/example_gadgets.cpp>
#include <vfhe/lattice_parameters.cpp>

/*
 * Represents the first layer in a specific field
 */
template <typename F>
struct layer1 {
    protoboard<F> pboard = protoboard<F>();
    layer1_gadget<F> gadget;
    std::vector<pb_ciphertext<F>> inputs, outputs;
    std::vector<std::vector<std::vector<F>>> input_scalars;
    std::vector<std::vector<F>> constant_term;

    layer1() : gadget(pboard) {}
    
    void init_random_weights() {
        input_scalars = std::vector<std::vector<std::vector<F>>>(outputs.size());
        constant_term = std::vector<std::vector<F>>(outputs.size());
        for (size_t j = 0; j < outputs.size(); ++j) {
            input_scalars[j] = std::vector<std::vector<F>>(inputs.size());
            for (size_t i = 0; i < inputs.size(); ++i) {
                input_scalars[j][i] = std::vector<F>(NTTsize);
                for (size_t k = 0; k < NTTsize; ++k)
                    input_scalars[j][i][k] = F::random_element();
            }
            constant_term[j] = std::vector<F>(NTTsize);
            for (size_t k = 0; k < NTTsize; ++k)
                constant_term[j][k] = F::random_element();
        }
    }

    // BGV elements are indistinguishable from random elements in R_Q
    // therefore we can test on random inputs
    void init_random_inputs() {
        for (size_t i = 0; i < inputs.size(); ++i)
            for (size_t j = 0; j < inputs.front().size(); ++j)
                for (size_t k = 0; k < NTTsize; ++k)
                    pboard.val(inputs[i][j][k]) = F::random_element();
    }
};

/*
 * Base class for the second layer in a specific field
 */
template <typename F>
struct layer2_proto {
    protoboard<F> pboard = protoboard<F>();
    std::vector<pb_variable_array<F>> rlk0, rlk1;
    std::vector<std::vector<pb_variable_array<F>>> c2s;
    std::vector<pb_ciphertext<F>> inputs, outputs;

    // Init inputs that come from first layer in same field
    void get_same_field_inputs(layer1<F>& gb1) {
        for (size_t j = 0; j < inputs.size(); ++j) {
            for (size_t i = 0; i < inputs.front().size()-1; ++i) {
                for (size_t k = 0; k < NTTsize; ++k)
                    pboard.val(inputs[j][i][k]) = gb1.pboard.val(gb1.outputs[j][i][k]).value;
            }
        }
        // rlks should also be indistinguishable from random elements in R_Q
        // therefore we can test on random rlks
        for (size_t i = 0; i < rlk0.size(); ++i) {
            for (size_t k = 0; k < NTTsize; ++k) {
                pboard.val(rlk0[i][k]) = F::random_element();
                pboard.val(rlk1[i][k]) = F::random_element();
            }
        }
    }

    // Fill in one element of c2 from layer1 in field Fpp1
    template <typename Fpp1>
    void drop_last_input_elt(layer1<typename Fpp1::Fp_type>& gb1) {
        for (size_t j = 0; j < inputs.size(); ++j)
            for (size_t k = 0; k < NTTsize; ++k)
                pboard.val(c2s[j][Fpp1::IND][k])
                    = gb1.pboard.val(gb1.outputs[j][gb1.outputs.front().size()-1][k]).value;
    }
};

/*
 * Represents second layer for fields that are removed by modswitch
 */
template <typename F>
struct layer2_ms : layer2_proto<F> {
    layermid_ms_gadget<F> gadget;

    layer2_ms() : gadget(this->pboard) {}
};

/*
 * Represents second layer for fields that remain after modswitch
 */
template <typename F>
struct layer2 : layer2_proto<F> {
    layermid_gadget<F> gadget;
    std::vector<pb_ciphertext<F>> to_removes;
    std::vector<std::vector<std::vector<F>>> input_scalars;
    std::vector<std::vector<F>> constant_term;

    layer2() : gadget(this->pboard) {}
    
    // TODO: make proto layer for layer2_proto and layer1?
    void init_random_weights() {
        input_scalars = std::vector<std::vector<std::vector<F>>>(this->outputs.size());
        constant_term = std::vector<std::vector<F>>(this->outputs.size());
        for (size_t j = 0; j < this->outputs.size(); ++j) {
            input_scalars[j] = std::vector<std::vector<F>>(this->inputs.size());
            for (size_t i = 0; i < this->inputs.size(); ++i) {
                input_scalars[j][i] = std::vector<F>(NTTsize);
                for (size_t k = 0; k < NTTsize; ++k)
                    input_scalars[j][i][k] = F::random_element();
            }
            constant_term[j] = std::vector<F>(NTTsize);
            for (size_t k = 0; k < NTTsize; ++k)
                constant_term[j][k] = F::random_element();
        }
    }

    // Inits extra input for modswitch that comes from layer2_ms'
    template <typename Ffrom>
    void init_to_removes_from(layer2_ms<Ffrom>& gbfrom) {
        for (size_t j = 0; j < to_removes.size(); ++j)
            for (size_t i = 0; i < to_removes.front().size(); ++i)
                for (size_t k = 0; k < NTTsize; ++k)
                    this->pboard.val(to_removes[j][i][k]) = gbfrom.pboard.val(gbfrom.outputs[j][i][k]).value;
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
    const size_t input_size, hidden_size, output_size;
    
    // Circuits for layer1 per field
    std::tuple<layer1<typename params::pp::Fp_type>...> layer1_boards;
    // Circuits for layer2_ms for field that will be removed
    typename last_from_pack<layer2_ms<typename params::pp::Fp_type>...>::type layer2_ms_board;
    // Circuits for layer2 per remaining field
    tuple_type_exceptlast<layer2<typename params::pp::Fp_type>...> layer2_boards;

    BGVexample(const size_t input_size, const size_t hidden_size, const size_t output_size)
        : input_size(input_size), hidden_size(hidden_size), output_size(output_size)
    { init<params...>(); }

    // Main init routine
    template <typename p, typename... ps>
    void init() {
        using F = typename p::pp::Fp_type;
        init_param<p>();
        init_layer1<p>();
        if constexpr (sizeof...(ps) >= modswitch_remove) {
            init_layer2<p, layer2<F>>(std::get<layer2<F>>(layer2_boards));
        } else {
            init_layer2<p, layer2_ms<F>>(layer2_ms_board);
        }
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
        gb.inputs = std::vector<pb_ciphertext<F>>(input_size);
        gb.outputs = std::vector<pb_ciphertext<F>>(hidden_size);
        
        for (size_t i = 0; i < input_size; ++i)
            gb.inputs[i].allocate(pb, input_deg, NTTsize);
        for (size_t j = 0; j < hidden_size; ++j)
            gb.outputs[j].allocate(pb, output_deg, NTTsize);
        
        pb.set_input_sizes(
            (input_size*input_deg + hidden_size*output_deg)*NTTsize);
        gb.init_random_weights();

        gb.gadget.initialize(
            gb.inputs, gb.input_scalars, gb.constant_term, gb.outputs);
        gb.gadget.generate_r1cs_constraints();
    }

    // Generate constraints of circuit in layer2 in specific field
    // can also be in field that will be removed by modswitched
    template <typename p, typename int_layer>
    void init_layer2(int_layer& gb) {
        using F = typename p::pp::Fp_type;
        constexpr bool ks_and_ms = std::is_same<int_layer, layer2<F>>::value;

        auto& pb = gb.pboard;
        gb.rlk0 = std::vector<pb_variable_array<F>>(rns_size);
        gb.rlk1 = std::vector<pb_variable_array<F>>(rns_size);
        for (size_t i = 0; i < rns_size; ++i) {
            gb.rlk0[i].allocate(pb, NTTsize);
            gb.rlk1[i].allocate(pb, NTTsize);
        }
        gb.inputs = std::vector<pb_ciphertext<F>>(hidden_size);
        gb.c2s = std::vector<std::vector<pb_variable_array<F>>>(hidden_size);
        for (size_t j = 0; j < hidden_size; ++j) {
            gb.inputs[j].allocate(pb, input_deg, NTTsize);
            gb.c2s[j] = std::vector<pb_variable_array<F>>(rns_size);
            for (size_t k = 0; k < rns_size; ++k)
                gb.c2s[j][k].allocate(pb, NTTsize);
        }
        size_t size_for_outputs = (ks_and_ms) ? output_size : hidden_size;
        gb.outputs = std::vector<pb_ciphertext<F>>(size_for_outputs);
        for (size_t i = 0; i < size_for_outputs; ++i)
            gb.outputs[i].allocate(pb, input_deg + ks_and_ms, NTTsize);
    
        if constexpr (ks_and_ms) {
            gb.to_removes = std::vector<pb_ciphertext<F>>(hidden_size);
            for (size_t j = 0; j < hidden_size; ++j)
                gb.to_removes[j].allocate(pb, input_deg, NTTsize);
            gb.init_random_weights();
            gb.gadget.initialize(
                gb.inputs, gb.input_scalars, gb.constant_term,
                gb.c2s, gb.rlk0, gb.rlk1, gb.to_removes,
                (F) PT_MOD, (F) prime_to_remove, gb.outputs);
        } else
            gb.gadget.initialize(
                gb.inputs, gb.c2s, gb.rlk0, gb.rlk1, (F) PT_MOD, gb.outputs);

        pb.set_input_sizes((ks_and_ms*output_size*output_deg
            + 2*input_deg*hidden_size + (2 + hidden_size)*rns_size)*NTTsize);
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
            layer2_ms<typename Fppfrom::Fp_type>& gb2 = layer2_ms_board;
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
            auto& gbto = layer2_ms_board;
            gbto.template drop_last_input_elt<Fppfrom>(gbfrom);
        }
    }
    
    // Calculate the circuits in layer2 that are not removed by modswitch
    template <typename p, typename... ps>
    void calculate_layer2_boards() {
        using Fpp = typename p::pp;
        using F = typename Fpp::Fp_type;
        auto& gb = std::get<layer2<F>>(layer2_boards);

        gb.init_to_removes_from(layer2_ms_board);
        gb.gadget.generate_r1cs_witness();
        
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
        return layer2_ms_board.pboard;
    }
};

#endif
