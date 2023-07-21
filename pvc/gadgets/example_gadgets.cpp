#ifndef PVC_EX_GADGETS
#define PVC_EX_GADGETS

#include <pvc/gadgets/gadgets.cpp>

using namespace libsnark;

/*
 * Generalization of vector_add_gadget
 * calculates (in NTT form)
 *     sum_j{left_input_scalar[j]left_inputs[j] + left_constant_term[j]}
 *     x
 *     sum_j{right_input_scalar[j]right_inputs[j] + right_constant_term[j]}
 */
template<typename FieldT>
class vector_lincomb_times_lincomb_gadget: public gadget<FieldT> {
public:
    pb_linear_combination_array<FieldT> A;
    pb_linear_combination_array<FieldT> B;
    pb_linear_combination_array<FieldT> C;

    vector_lincomb_times_lincomb_gadget(protoboard<FieldT>& pb,
        const std::vector<pb_variable_array<FieldT>>& left_inputs,
        const std::vector<pb_variable_array<FieldT>>& right_inputs,
        const pb_variable_array<FieldT>& output,
        const std::vector<pb_variable_array<FieldT>>& left_input_scalars
            = std::vector<pb_variable_array<FieldT>>(),
        const std::vector<pb_variable_array<FieldT>>& right_input_scalars
            = std::vector<pb_variable_array<FieldT>>(),
        const pb_variable_array<FieldT>& left_constant_term=pb_variable_array<FieldT>(),
        const pb_variable_array<FieldT>& right_constant_term=pb_variable_array<FieldT>(),
        const FieldT output_scalar=FieldT::zero(),
        const std::string& annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix)
    {
        size_t in_size = left_inputs.size();
        assert(in_size > 0 && in_size == right_inputs.size());
        size_t out_size = output.size();
        assert(out_size > 0);
        assert(std::all_of(left_inputs.begin(), left_inputs.end(),
            [&output](pb_variable_array<FieldT> l_input) {
                return l_input.size() == out_size
                    && (left_constant_term.size() == 0
                    || left_constant_term.size() == l_input.size());
            }));
        assert(std::all_of(right_inputs.begin(), right_inputs.end(),
            [&output](pb_variable_array<FieldT> r_input) {
                return r_input.size() == out_size
                    && (right_constant_term.size() == 0
                    || right_constant_term.size() == r_input.size());
            }));
        size_t lis_size = left_input_scalars.size();
        assert(lis_size == 0 || lis_size == in_size);
        assert(std::all_of(left_input_scalars.begin(), left_input_scalars.end(),
            [&output](pb_variable_array<FieldT> l_input_sc) { return l_input_sc.size() == out_size; }));
        size_t ris_size = right_input_scalars.size();
        assert(ris_size == 0 || ris_size == in_size);
        assert(std::all_of(right_input_scalars.begin(), right_input_scalars.end(),
            [&output](pb_variable_array<FieldT> r_input_sc) { return r_input_sc.size() == out_size; }));

        for (size_t i = 0; i < out_size; ++i) {
            linear_combination<FieldT> lcA{}, lcB{};
            for (size_t j = 0; j < in_size; ++j) {
                if (lis_size == 0) lcA.add_term(left_inputs[j][i]);
                else lcA.add_term(left_inputs[j][i], left_input_scalars[j][i]);
                if (ris_size == 0) lcB.add_term(right_inputs[j][i]);
                else lcB.add_term(right_inputs[j][i], right_input_scalars[j][i]);
            }
            if (left_constant_term.size() != 0) lcA.add_term(left_constant_term[i]);
            if (right_constant_term.size() != 0) lcB.add_term(right_constant_term[i]);
            pb_linear_combination<FieldT> pblcA{}, pblcB{};
            pblcA.assign(pb, lcA); A.emplace_back(pblcA);
            pblcB.assign(pb, lcB); B.emplace_back(pblcB);
        }
        if (output_scalar == FieldT::zero())
            C = pb_linear_combination_array<FieldT>(output);
        else {
            for (size_t i = 0; i < out_size; ++i) {
                linear_combination<FieldT> lcC{}; lcC.add_term(output[i], output_scalar);
                pb_linear_combination<FieldT> pblcC{}; pblcC.assign(this->pb, lcC);
                C.emplace_back(pblcC);
            }
        }
    }
    void generate_r1cs_constraints() {
        for (size_t i = 0; i < A.size(); ++i)
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(A[i], B[i], C[i]));
    }
    void generate_r1cs_witness() {
        for (size_t i = 0; i < A.size(); ++i) {
            A[i].evaluate(this->pb);
            B[i].evaluate(this->pb);

            this->pb.lc_val(C[i]) = this->pb.lc_val(A[i]) * this->pb.lc_val(B[i]);
            if (!C[i].is_variable) {
                assert(C[i].terms.size() == 1);
                this->pb.val(pb_variable<FieldT>(C[i].terms.front().index)) =
                    this->pb.lc_val(C[i]) * C[i].terms.front().coeff.inverse();
            }
        }
    }
};

template<typename FieldT>
class ct_lincomb_square_gadget: public gadget<FieldT> {
public:
    std::vector<vector_lincomb_times_lincomb_gadget<FieldT>> inner_gadgets;
    
    ct_lincomb_square_gadget(protoboard<FieldT>&pb,
        const std::vector<pb_ciphertext<FieldT>>& inputs,
        const std::vector<pb_variable_array<FieldT>>& input_scalars,
        const pb_variable_array<FieldT>& constant_term,
        const pb_ciphertext<FieldT>& output,
        const std::string& annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix)
    {
        size_t in_size = inputs.size();
        assert(in_size > 0);
        assert(output.size() == 3);
        assert(std::all_of(inputs.begin(), inputs.end(),
            [&output](pb_ciphertext<FieldT> input){ return input.size() == 2; }));

        std::vector<pb_variable_array<FieldT>> c0_inputs, c1_inputs;
        for (size_t i = 0; i < in_size; ++i) {
            c0_inputs.emplace_back(inputs[i][0]);
            c1_inputs.emplace_back(inputs[i][1]);
        }
        inner_gadgets.emplace_back(vector_lincomb_times_lincomb_gadget<FieldT>(pb,
            c0_inputs, c0_inputs, output[0], input_scalars, input_scalars,
            constant_term, constant_term));
        inner_gadgets.emplace_back(vector_lincomb_times_lincomb_gadget<FieldT>(pb,
            c0_inputs, c1_inputs, output[1], input_scalars, input_scalars,
            constant_term, pb_variable_array<FieldT>(), FieldT(2).inverse()));
        inner_gadgets.emplace_back(vector_lincomb_times_lincomb_gadget<FieldT>(pb,
            c1_inputs, c1_inputs, output[2], input_scalars, input_scalars));
    }
    void generate_r1cs_constraints() { for (auto &g : inner_gadgets) { g.generate_r1cs_constraints(); }}
    void generate_r1cs_witness() { for (auto &g : inner_gadgets) { g.generate_r1cs_witness(); }}
};

template<typename FieldT>
class layer1_gadget: public gadget<FieldT> {
public:
    std::vector<NTT_gadget<FieldT>> iNTTgadgets;
    std::vector<ct_lincomb_square_gadget<FieldT>> comp_gadgets;

    layer1_gadget(
        protoboard<FieldT>& pb,
        const std::string& annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {};
    void initialize(
        const std::vector<pb_ciphertext<FieldT>>& inputs,
        const std::vector<std::vector<pb_variable_array<FieldT>>>& input_scalars,
        const std::vector<pb_variable_array<FieldT>>& constant_term,
        const std::vector<pb_ciphertext<FieldT>>& outputs
    ) {
        size_t out_size = outputs.size();
        assert(out_size > 0);
        assert(outputs[0].size() > 0);
        size_t el_length = outputs[0][0].size();
        assert(input_scalars.size() == out_size);
        assert(constant_term.size() == out_size);

        for (size_t i = 0; i < out_size; ++i) {
            pb_ciphertext<FieldT> NTT_output;
            NTT_output.push_back(outputs[i][0], outputs[i][1]);
            NTT_output.emplace_back(pb_variable_array<FieldT>());
            NTT_output[2].allocate(this->pb, el_length);
            comp_gadgets.emplace_back(ct_lincomb_square_gadget<FieldT>(this->pb,
                inputs, input_scalars[i], constant_term[i], NTT_output));
            iNTTgadgets.emplace_back(NTT_gadget<FieldT>(this->pb,
                NTT_output[2], outputs[i][2]));
        }
    }
    void generate_r1cs_constraints() {
        for (auto &g : comp_gadgets) g.generate_r1cs_constraints();
        for (auto &g : iNTTgadgets) g.generate_r1cs_constraints();
    }
    void generate_r1cs_witness() {
        for (auto &g : comp_gadgets) g.generate_r1cs_witness();
        for (auto &g : iNTTgadgets) g.generate_r1cs_witness();
    }
};

template<typename FieldT>
class layer2_ms_gadget: public gadget<FieldT> {
public:
    std::vector<relinearize_gadget<FieldT>> relin_gadgets;

    layer2_ms_gadget(protoboard<FieldT>& pb,
        const std::string& annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {}
    void initialize(
        const std::vector<pb_variable_array<FieldT>>& inputs,
        const std::vector<std::vector<pb_variable_array<FieldT>>> &decomps,
        const std::vector<pb_variable_array<FieldT>> &rlkkey0,
        const std::vector<pb_variable_array<FieldT>> &rlkkey1,
        const FieldT& pt_mod,
        std::vector<pb_ciphertext<FieldT>>& outputs
    ) {
        size_t in_size = inputs.size();
        assert(in_size > 0);
        assert(decomps.size() == in_size);
        assert(outputs.size() == in_size);

        for (size_t i = 0; i < in_size; ++i) {
            relin_gadgets.emplace_back(relinearize_gadget<FieldT>(
                inputs[i], decomps[i], rlkkey0, rlkkey1, outputs[i], pt_mod));
        }
    }
    void generate_r1cs_constraints() { for (auto &g : relin_gadgets) g.generate_r1cs_constraints(); }
    void generate_r1cs_witness() { for (auto &g : relin_gadgets) g.generate_r1cs_witness(); }
};

template<typename FieldT>
class layer2_gadget: public gadget<FieldT> {
public:
    std::vector<relinearize_modswitch_gadget<FieldT>> relin_ms_gadgets;
    std::vector<ct_lincomb_square_gadget<FieldT>> comp_gadgets;

    layer2_gadget(protoboard<FieldT>& pb,
        const std::string& annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {}
    void initialize(
        const std::vector<pb_ciphertext<FieldT>>& inputs,
        const std::vector<std::vector<pb_variable_array<FieldT>>>& input_scalars,
        const std::vector<pb_variable_array<FieldT>>& constant_term,
        const std::vector<std::vector<pb_variable_array<FieldT>>> &decomps,
        const std::vector<pb_variable_array<FieldT>> &rlkkey0,
        const std::vector<pb_variable_array<FieldT>> &rlkkey1,
        const std::vector<pb_ciphertext<FieldT>>& to_removes,
        const FieldT pt_mod,
        const FieldT q_toremove,
        std::vector<pb_ciphertext<FieldT>>& outputs
    ) {
        size_t in_size = inputs.size();
        assert(in_size > 0);
        assert(decomp.size() == in_size);
        assert(to_remove.size() == in_size);
        size_t out_size = outputs.size();
        assert(out_size > 0);
        assert(outputs[0].size() > 0);
        size_t el_length = outputs[0][0].size();
        assert(input_scalars.size() == out_size);
        assert(constant_term.size() == out_size);
        
        std::vector<pb_ciphertext<FieldT>> inters;
        for (size_t i = 0; i < in_size; ++i) {
            inters.emplace_back(pb_ciphertext<FieldT>());
            inters[i].allocate(this->pb, 3, el_length);
            relin_ms_gadgets.emplace_back(relinearize_modswitch_gadget<FieldT>(
                inputs[i], decomps[i], rlkkey0, rlkkey1, to_removes[i], pt_mod, q_toremove, inters[i]));
        }
        for (size_t i = 0; i < out_size; ++i) {
            comp_gadgets.emplace_back(ct_lincomb_square_gadget<FieldT>(
                inputs, input_scalars[i], constant_term[i], outputs[i]));
        }
    }
    void generate_r1cs_constraints() {
        for (auto &g : relin_ms_gadgets) g.generate_r1cs_constraints();
        for (auto &g : comp_gadgets) g.generate_r1cs_constraints();
    }
    void generate_r1cs_witness() {
        for (auto &g : relin_ms_gadgets) g.generate_r1cs_witness();
        for (auto &g : comp_gadgets) g.generate_r1cs_witness();
    }
};

#endif
