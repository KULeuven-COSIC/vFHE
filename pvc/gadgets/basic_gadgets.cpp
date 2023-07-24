#ifndef PVC_GADGETS
#define PVC_GADGETS

#include <libsnark/gadgetlib1/gadget.hpp>
#include <pvc/gadgets/pb_ciphertext.cpp>

using namespace libsnark;

// Gadget that adds vectors
template<typename FieldT>
class vector_add_gadget : public gadget<FieldT> {
public:
    pb_linear_combination_array<FieldT> A;
    pb_linear_combination_array<FieldT> B;
    pb_linear_combination_array<FieldT> C;

    vector_add_gadget(protoboard<FieldT>& pb,
        const std::vector<pb_variable_array<FieldT>> &inputs,
        const pb_variable_array<FieldT> &output,
        FieldT output_scalar=FieldT::zero(), // divide by this scalar at the end
        const std::vector<FieldT>& input_scalars=std::vector<FieldT>(), // multiply inputs by these scalars
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix)
    {
        assert(output.size() > 0);
        assert(std::all_of(inputs.begin(), inputs.end(),
            [&output](pb_variable_array<FieldT> input) {
                return input.size() == output.size();
            }));
        size_t in_sc_size = input_scalars.size();
        assert(in_sc_size == 0 || in_sc_size == inputs.size());
        
        for (size_t i = 0; i < output.size(); ++i) {
            A.emplace_back(pb_linear_combination<FieldT>(ONE));
            linear_combination<FieldT> lc{};
            for (size_t j = 0; j < inputs.size(); ++j) {
                if (in_sc_size == 0) lc.add_term(inputs[j][i]);
                else lc.add_term(inputs[j][i], input_scalars[j]);
            }
            pb_linear_combination<FieldT> pblc{};
            pblc.assign(pb, lc);
            B.emplace_back(pblc);
        }
        if (output_scalar == FieldT::zero())
            C = pb_linear_combination_array<FieldT>(output);
        else {
            for (size_t i = 0; i < output.size(); ++i) {
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
            // same as with NTT gadget
            if (!C[i].is_variable) {
                assert(C[i].terms.size() == 1);
                this->pb.val(pb_variable<FieldT>(C[i].terms.front().index)) =
                    this->pb.lc_val(C[i]) * C[i].terms.front().coeff.inverse();
            }
        }
    }
};

// Gadget that multiplies vectors
template<typename FieldT>
class vector_mult_gadget : public gadget<FieldT> {
public:
    pb_linear_combination_array<FieldT> A;
    pb_linear_combination_array<FieldT> B;
    const pb_linear_combination_array<FieldT> C;

    vector_mult_gadget(protoboard<FieldT>& pb,
        const pb_variable_array<FieldT> &left,
        const pb_variable_array<FieldT> &right,
        const pb_variable_array<FieldT> &out,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix), A(left), B(right), C(out)
    {
        assert(left.size() >= 1);
        assert(left.size() == right.size());
        assert(left.size() == out.size());
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < A.size(); ++i) {
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(A[i], B[i], C[i]));
        }
    }
    void generate_r1cs_witness() {
        for (size_t i = 0; i < A.size(); ++i) {
            A[i].evaluate(this->pb);
            B[i].evaluate(this->pb);

            this->pb.lc_val(C[i]) = this->pb.lc_val(A[i]) * this->pb.lc_val(B[i]);
        }
    }
};

// Gadget that adds ciphertexts
template<typename FieldT>
class ct_add_gadget : public gadget<FieldT> {
public:
    std::vector<vector_add_gadget<FieldT>> inner_gadgets;
    
    // For some gadgets, we will split up constructor like this
    // Could do it for all but is less readable
    ct_add_gadget(protoboard<FieldT>& pb,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {}
    void initialize(
        const std::vector<pb_ciphertext<FieldT>> &inputs,
        const pb_ciphertext<FieldT> &output
    ) {
        assert(output.size() > 0);
        assert(std::all_of(inputs.begin(), inputs.end(),
            [&output](pb_ciphertext<FieldT> input){
                return input.size() == output.size();
            }));

        // loop over ciphertext coefficients
        for (size_t i = 0; i < inputs.front().size(); ++i) {
            std::vector<pb_variable_array<FieldT>> adder_inputs;
            // loop over ciphertexts
            for (size_t j = 0; j < inputs.size(); ++j) {
                adder_inputs.emplace_back(inputs[j][i]);
            }
            inner_gadgets.emplace_back(vector_add_gadget<FieldT>(this->pb, adder_inputs, output[i]));
        }
    }
    void generate_r1cs_constraints() { for (auto &g : inner_gadgets) { g.generate_r1cs_constraints(); }}
    void generate_r1cs_witness() { for (auto &g : inner_gadgets) { g.generate_r1cs_witness(); }}
};

// Gadgets that multiplies ciphertexts
template<typename FieldT>
class ct_mult_gadget : public gadget<FieldT> {
public:
    std::vector<vector_add_gadget<FieldT>> inner_add_gadgets;
    std::vector<vector_mult_gadget<FieldT>> inner_mult_gadgets;

    ct_mult_gadget(protoboard<FieldT>& pb,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {}
    void initialize(
        const pb_ciphertext<FieldT> &left,
        const pb_ciphertext<FieldT> &right,
        const pb_ciphertext<FieldT> &output
    ) {
        size_t is = left.size();
        size_t os = output.size();
        assert(is == right.size());
        assert(os == 2*is - 1);

        // loop over other output ciphertext coefficients
        inner_mult_gadgets.emplace_back(vector_mult_gadget<FieldT>(this->pb, left[0], right[0], output[0]));
        for (size_t i = 1; i < os-1; ++i) {
            std::vector<pb_variable_array<FieldT>> temps;
            size_t start = (i > is-1) ? i-(is-1) : 0;
            size_t end = i - start;
            for (size_t j = start; j <= end; ++j) {
                temps.emplace_back(pb_variable_array<FieldT>());
                temps[j-start].allocate(this->pb, left[j].size());
                inner_mult_gadgets.emplace_back(vector_mult_gadget<FieldT>(this->pb, left[j], right[i-j], temps[j-start]));
            }
            inner_add_gadgets.emplace_back(vector_add_gadget<FieldT>(this->pb, temps, output[i]));
        }
        inner_mult_gadgets.emplace_back(vector_mult_gadget<FieldT>(this->pb, left[is-1], right[is-1], output[os-1]));
    }
    void generate_r1cs_constraints() {
        for (auto &g : inner_mult_gadgets) { g.generate_r1cs_constraints(); }
        for (auto &g : inner_add_gadgets) { g.generate_r1cs_constraints(); }
    }
    void generate_r1cs_witness() {
        for (auto &g : inner_mult_gadgets) { g.generate_r1cs_witness(); }
        for (auto &g : inner_add_gadgets) { g.generate_r1cs_witness(); }
    }
};

// Gadgets for inner product of ciphertexts
template<typename FieldT>
class ct_inner_product_gadget : public gadget<FieldT> {
public:
    std::vector<ct_mult_gadget<FieldT>> inner_mult_gadgets;
    std::vector<ct_add_gadget<FieldT>> inner_add_gadgets;

    ct_inner_product_gadget() {};

    ct_inner_product_gadget(protoboard<FieldT>& pb,
        const std::vector<pb_ciphertext<FieldT>> &left,
        const std::vector<pb_ciphertext<FieldT>> &right,
        const pb_ciphertext<FieldT> &output,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix)
    {

        size_t vec_length = left.size();
        assert(vec_length > 0);
        size_t deg = left[0].size();
        assert(deg > 0);
        size_t el_length = left[0][0].size();
        assert(el_length > 0);

        assert(right.size() == vec_length);
        assert(std::equal(left.begin(), left.end(), right.begin(),
            [deg](pb_ciphertext<FieldT> l, pb_ciphertext<FieldT> r){
                return (l.size() == deg && r.size() == deg);
            }));
        assert(output.size() == 2*deg - 1);

        std::vector<pb_ciphertext<FieldT>> temps;
        for (size_t i = 0; i < vec_length; ++i) {
            pb_ciphertext<FieldT> temp;
            temps.emplace_back(temp);
        }
        for (size_t i = 0; i < vec_length; ++i) {
            temps[i].allocate(pb, 2*deg-1, el_length);
            ct_mult_gadget<FieldT> mult_g = ct_mult_gadget<FieldT>(pb);
            mult_g.initialize(left[i], right[i], temps[i]);
            inner_mult_gadgets.emplace_back(mult_g);
        }
        ct_add_gadget<FieldT> add_g = ct_add_gadget<FieldT>(pb);
        add_g.initialize(temps, output);
        inner_add_gadgets.emplace_back(add_g);
    }
    void generate_r1cs_constraints() {
        for (auto &g : inner_mult_gadgets) { g.generate_r1cs_constraints(); }
        for (auto &g : inner_add_gadgets) { g.generate_r1cs_constraints(); }
    }
    void generate_r1cs_witness() {
        for (auto &g : inner_mult_gadgets) { g.generate_r1cs_witness(); }
        for (auto &g : inner_add_gadgets) { g.generate_r1cs_witness(); }
    }
};

// Gadget for (inverse) Number Theoretic Transform
template <typename FieldT>
class NTT_gadget : gadget<FieldT> {
public:

    pb_linear_combination_array<FieldT> A;
    pb_linear_combination_array<FieldT> B;
    pb_linear_combination_array<FieldT> C;

    NTT_gadget(protoboard<FieldT>& pb,
        const pb_variable_array<FieldT>& input,
        const pb_variable_array<FieldT>& output,
        bool inverse=false,
        const std::string& annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix)
    {
        const size_t n = input.size();
        assert(n == output.size());
        const size_t logn = log2(n);
        assert((size_t) (1 << logn) == n);

        assert((FieldT::root_of_unity^(1 << FieldT::s)) == FieldT::one());
        FieldT psi = FieldT::root_of_unity^(1 << (FieldT::s - logn - 1));
        FieldT w = psi^2;
        assert((psi^(n << 1)) == FieldT::one());
        assert((w^n) == FieldT::one());
        if (inverse)
            w.invert();
    
        // For testing using Sage NTT
        //std::cout << psi << std::endl;
        //std::cout << w << std::endl;

        pb_variable_array<FieldT> prev = input;
        for (size_t s = 1; s <= logn; ++s) {
            pb_variable_array<FieldT> next;
            if (s != logn) next.allocate(pb, n);
            else next = output;

            size_t m = 1 << s;
            FieldT wm = w^(1 << (logn - s));
            assert((wm^m) == FieldT::one());

            for (size_t k = 0; k < n; k+=m) {
                FieldT wt = FieldT::one();
                for (size_t j = 0; j < (m >> 1); ++j) {
                    size_t i1 = k + j;
                    size_t i2 = k + j + (m >> 1);
                    size_t pi1 = (s != 1) ? i1 : libff::bitreverse(i1, logn);
                    size_t pi2 = (s != 1) ? i2 : libff::bitreverse(i2, logn);
                    // extra coefficients for B
                    FieldT cB1 = (!inverse && s == 1) ? psi^(pi1) : FieldT::one();
                    FieldT cB2 = (!inverse && s == 1) ? psi^(pi2) : FieldT::one();
                    // extra coefficients for C
                    FieldT cC1 = (inverse && s == logn) ? FieldT(n)*(psi^i1) : FieldT::one();
                    FieldT cC2 = (inverse && s == logn) ? FieldT(n)*(psi^i2) : FieldT::one();
                    {
                    // A
                    A.emplace_back(pb_linear_combination<FieldT>(ONE));
                    // B
                    linear_combination<FieldT> lcB{};
                    lcB.add_term(prev[pi1], cB1);
                    lcB.add_term(prev[pi2], wt*cB2);
                    pb_linear_combination<FieldT> pblcB{}; pblcB.assign(pb, lcB);
                    B.emplace_back(pblcB);
                    // C
                    linear_combination<FieldT> lcC{};
                    lcC.add_term(next[i1], cC1);
                    pb_linear_combination<FieldT> pblcC{}; pblcC.assign(pb, lcC);
                    C.emplace_back(pblcC);
                    }{
                    // A
                    A.emplace_back(pb_linear_combination<FieldT>(ONE));
                    // B 
                    linear_combination<FieldT> lcB{};
                    lcB.add_term(prev[pi1], cB1);
                    lcB.add_term(prev[pi2], (-wt)*cB2);
                    pb_linear_combination<FieldT> pblcB{}; pblcB.assign(pb, lcB);
                    B.emplace_back(pblcB);
                    // C 
                    linear_combination<FieldT> lcC{};
                    lcC.add_term(next[i2], cC2);
                    pb_linear_combination<FieldT> pblcC{}; pblcC.assign(pb, lcC);
                    C.emplace_back(pblcC);
                    }
                    wt *= wm;
                }
            }
            prev = next;
        }
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < A.size(); ++i)
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(A[i], B[i], C[i]));
    }
    void generate_r1cs_witness() {
        // same as with vector add gadget
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

// Gadget for relinearizing one ciphertext
template<typename FieldT>
class relinearize_gadget : public gadget<FieldT> {
public:
    std::vector<NTT_gadget<FieldT>> NTT_gadgets;
    std::vector<NTT_gadget<FieldT>> iNTT_gadgets;
    std::vector<vector_mult_gadget<FieldT>> mult_gadgets;
    std::vector<vector_add_gadget<FieldT>> add_gadgets;

    relinearize_gadget(protoboard<FieldT>& pb,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {}
    void initialize(
        const pb_ciphertext<FieldT> &input,
        const std::vector<pb_variable_array<FieldT>> &decomp,
        const std::vector<pb_variable_array<FieldT>> &rlkkey0,
        const std::vector<pb_variable_array<FieldT>> &rlkkey1,
        const pb_ciphertext<FieldT> &output,
        const FieldT& pt_mod = FieldT::zero() // divide by this scalar at the end if non-zero
    ) {

        size_t vec_length = decomp.size();
        assert(vec_length > 0);
        assert(vec_length == rlkkey0.size());
        assert(vec_length == rlkkey1.size());
        size_t array_length = decomp.front().size();
        assert(input.size() == 2);
        assert(output.size() == 2);
        
        // NTT the decomposition
        std::vector<pb_variable_array<FieldT>> decomp_NTT;
        for (size_t i = 0; i < vec_length; ++i) {
            pb_variable_array<FieldT> temp_NTT;
            temp_NTT.allocate(this->pb, array_length);
            decomp_NTT.emplace_back(temp_NTT);
            NTT_gadgets.emplace_back(NTT_gadget<FieldT>(this->pb, decomp[i], decomp_NTT[i]));
        }
        
        // inner product multiplications of rlkkey and decomp
        std::vector<pb_variable_array<FieldT>> temps0, temps1;
        temps0.push_back(input[0]);
        temps1.push_back(input[1]);
        for (size_t i = 0; i < vec_length; ++i) {
            temps0.emplace_back(pb_variable_array<FieldT>()); temps0[i+1].allocate(this->pb, array_length);
            temps1.emplace_back(pb_variable_array<FieldT>()); temps1[i+1].allocate(this->pb, array_length);
            mult_gadgets.emplace_back(vector_mult_gadget<FieldT>(this->pb, decomp_NTT[i], rlkkey0[i], temps0[i+1]));
            mult_gadgets.emplace_back(vector_mult_gadget<FieldT>(this->pb, decomp_NTT[i], rlkkey1[i], temps1[i+1]));
        }
        
        // inner product additions
        if (pt_mod == FieldT::zero()) {
            add_gadgets.emplace_back(vector_add_gadget<FieldT>(this->pb, temps0, output[0]));
            add_gadgets.emplace_back(vector_add_gadget<FieldT>(this->pb, temps1, output[1]));
        } else {
            // and iNTT + division by pt_mod if pt_mod is non-zero
            pb_ciphertext<FieldT> output_NTT;
            output_NTT.allocate(this->pb, 2, array_length);
            add_gadgets.emplace_back(vector_add_gadget<FieldT>(this->pb, temps0, output_NTT[0], pt_mod));
            add_gadgets.emplace_back(vector_add_gadget<FieldT>(this->pb, temps1, output_NTT[1], pt_mod));
            for (size_t i = 0; i < 2; ++i)
                iNTT_gadgets.emplace_back(NTT_gadget<FieldT>(this->pb, output_NTT[i], output[i]));
        }
    }
    void generate_r1cs_constraints() {
        for (auto &g : NTT_gadgets) { g.generate_r1cs_constraints(); }
        for (auto &g : mult_gadgets) { g.generate_r1cs_constraints(); }
        for (auto &g : add_gadgets) { g.generate_r1cs_constraints(); }
        for (auto &g : iNTT_gadgets) { g.generate_r1cs_constraints(); }
    }
    void generate_r1cs_witness() {
        for (auto &g : NTT_gadgets) { g.generate_r1cs_witness(); }
        for (auto &g : mult_gadgets) { g.generate_r1cs_witness(); }
        for (auto &g : add_gadgets) { g.generate_r1cs_witness(); }
        for (auto &g : iNTT_gadgets) { g.generate_r1cs_witness(); }
    }
};

// Gadget for modswitching one ciphertext
template<typename FieldT>
class modswitch_gadget : public gadget<FieldT> {
public:
    std::vector<vector_add_gadget<FieldT>> inner_gadgets;

    modswitch_gadget(protoboard<FieldT>& pb,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix) {}
    void initialize(
        const pb_ciphertext<FieldT>& input,
        const pb_ciphertext<FieldT>& to_remove, // assumed already in NTT form
        const FieldT& pt_mod,
        const FieldT& q_toremove,
        const pb_ciphertext<FieldT>& output
    ) {
        std::vector<FieldT> input_scalars{FieldT::one(), -pt_mod};
        for (size_t i = 0; i < 2; ++i) {
            std::vector<pb_variable_array<FieldT>> add_inputs{input[i], to_remove[i]};
            inner_gadgets.emplace_back(
                vector_add_gadget<FieldT>(this->pb, add_inputs, output[i], q_toremove, input_scalars));
        }
    }
    void generate_r1cs_constraints() {
        for (auto &g : inner_gadgets) { g.generate_r1cs_constraints(); }
    }
    void generate_r1cs_witness() {
        for (auto &g : inner_gadgets) { g.generate_r1cs_witness(); }
    }
};

// Gadget for merged relinearization and modswitch circuits
template<typename FieldT>
class relinearize_modswitch_gadget : public gadget<FieldT> {
public:
    relinearize_gadget<FieldT> relin_gadget;
    std::vector<NTT_gadget<FieldT>> NTT_gadgets;
    modswitch_gadget<FieldT> ms_gadget;

    relinearize_modswitch_gadget(protoboard<FieldT>& pb,
        const std::string &annotation_prefix=""
    ) : gadget<FieldT>(pb, annotation_prefix), relin_gadget(pb), ms_gadget(pb) {}
    void initialize(
        const pb_ciphertext<FieldT> &input,
        const std::vector<pb_variable_array<FieldT>> &decomp,
        const std::vector<pb_variable_array<FieldT>> &rlkkey0,
        const std::vector<pb_variable_array<FieldT>> &rlkkey1,
        const pb_ciphertext<FieldT>& to_remove,
        const FieldT pt_mod,
        const FieldT q_toremove,
        const pb_ciphertext<FieldT>& output
    ) {
        assert(input.size() == 2);
        assert(to_remove.size() == 2);
        assert(output.size() == 2);
        assert(pt_mod != FieldT::zero());
        assert(q_toremove != FieldT::zero());
        size_t array_length = input[0].size();

        pb_ciphertext<FieldT> inter;
        inter.allocate(this->pb, 2, array_length);
        relin_gadget.initialize(input, decomp, rlkkey0, rlkkey1, inter);
        
        pb_ciphertext<FieldT> to_remove_NTT;
        to_remove_NTT.allocate(this->pb, 2, array_length);
        for (size_t i = 0; i < 2; ++i)
            NTT_gadgets.emplace_back(NTT_gadget<FieldT>(this->pb, to_remove[i], to_remove_NTT[i]));

        ms_gadget.initialize(inter, to_remove_NTT, pt_mod, q_toremove, output);
    }
    void generate_r1cs_constraints() {
        relin_gadget.generate_r1cs_constraints();
        for (auto &g : NTT_gadgets) { g.generate_r1cs_constraints(); }
        ms_gadget.generate_r1cs_constraints();
    }
    void generate_r1cs_witness() {
        relin_gadget.generate_r1cs_witness();
        for (auto &g : NTT_gadgets) { g.generate_r1cs_witness(); }
        ms_gadget.generate_r1cs_witness();
    }
};

#endif
