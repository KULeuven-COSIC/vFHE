#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "pvc/gadgets/gadgets.cpp"
#include "pvc/gadgets/example_gadgets.cpp"

// Some consistency tests for gadgets

using std::vector;

using namespace libsnark;

template <typename FieldT>
r1cs_example<FieldT> test_vector_add_gadget(const size_t vector_length)
{
    protoboard<FieldT> pb;

    pb_variable_array<FieldT> vec1, vec2, vec3, out;
    std::vector<pb_variable_array<FieldT>> inputs = {vec1, vec2, vec3};

    for (auto &pbva : inputs) { pbva.allocate(pb, vector_length); }
    out.allocate(pb, vector_length);


    vector_add_gadget<FieldT> g(pb, inputs, out);
    g.generate_r1cs_constraints();

    for (size_t i = 0; i < vector_length; ++i) {
        for (auto &pbva : inputs) {
            pb.val(pbva[i]) = FieldT::random_element();
        }
    }

    g.generate_r1cs_witness();

    pb.set_input_sizes(2*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template <typename FieldT>
r1cs_example<FieldT> test_vector_mult_gadget(const size_t vector_length)
{
    protoboard<FieldT> pb;

    pb_variable_array<FieldT> left, right, out;

    left.allocate(pb, vector_length);
    right.allocate(pb, vector_length);
    out.allocate(pb, vector_length);

    vector_mult_gadget<FieldT> g(pb, left, right, out);
    g.generate_r1cs_constraints();

    for (size_t i = 0; i < vector_length; ++i) {
        pb.val(left[i]) = FieldT::random_element();
        pb.val(right[i]) = FieldT::random_element();
    }

    g.generate_r1cs_witness();

    pb.set_input_sizes(2*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_ct_add_gadget(const size_t vector_length)
{
    protoboard<FieldT> pb;

    pb_ciphertext<FieldT> c0, c1, c2, c3;
    c0.allocate(pb, 2, vector_length);
    c1.allocate(pb, 2, vector_length);
    c2.allocate(pb, 2, vector_length);
    c3.allocate(pb, 2, vector_length);

    std::vector<pb_ciphertext<FieldT>> inputs = {c0, c1, c2};

    ct_add_gadget<FieldT> g(pb);
    g.initialize(inputs, c3);
    g.generate_r1cs_constraints();

    for (size_t j = 0; j < 2; ++j) {
        for (size_t i = 0; i < vector_length; ++i)
        {
            pb.val(c0[j][i]) = FieldT::random_element();
            pb.val(c1[j][i]) = FieldT::random_element();
            pb.val(c2[j][i]) = FieldT::random_element();
        }
    }

    g.generate_r1cs_witness();

    pb.set_input_sizes(2*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_ct_mult_gadget(const size_t vector_length)
{
    protoboard<FieldT> pb;
    pb_ciphertext<FieldT> c0, c1, c2;

    c0.allocate(pb, 3, vector_length);
    c1.allocate(pb, 3, vector_length);
    c2.allocate(pb, 5, vector_length);

    ct_mult_gadget<FieldT> g(pb);
    g.initialize(c0, c1, c2);
    g.generate_r1cs_constraints();

    for (size_t j = 0; j < 3; ++j) {
        for (size_t i = 0; i < vector_length; ++i)
        {
            pb.val(c0[j][i]) = FieldT::random_element();
            pb.val(c1[j][i]) = FieldT::random_element();
        }
    }

    g.generate_r1cs_witness();
    
    pb.set_input_sizes(2*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_ct_inner_product_gadget(const size_t vector_length, const size_t CTvec_size)
{
    protoboard<FieldT> pb;

    std::vector<pb_ciphertext<FieldT>> CvecA, CvecB;
    for (size_t i = 0; i < CTvec_size; ++i) {
        pb_ciphertext<FieldT> CA, CB;
        CA.allocate(pb, 2, vector_length);
        CB.allocate(pb, 2, vector_length);
        CvecA.emplace_back(CA);
        CvecB.emplace_back(CB);
    }

    pb_ciphertext<FieldT> Cres;
    Cres.allocate(pb, 3, vector_length);

    ct_inner_product_gadget<FieldT> g(pb, CvecA, CvecB, Cres);
    g.generate_r1cs_constraints();

    for (size_t k = 0; k < CTvec_size; ++k) {
        for (size_t j = 0; j < 2; ++j) {
            for (size_t i = 0; i < vector_length; ++i)
            {
                pb.val(CvecA[k][j][i]) = FieldT::random_element();
                pb.val(CvecB[k][j][i]) = FieldT::random_element();
            }
        }
    }

    g.generate_r1cs_witness();

    pb.set_input_sizes(2*CTvec_size*2*vector_length + 3*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_NTT_gadget(const size_t vector_length)
{
    protoboard<FieldT> pb;

    pb_variable_array<FieldT> input, output;
    input.allocate(pb, vector_length);
    output.allocate(pb, vector_length);

    //NTT_gadget<FieldT> g(pb, input, output, false);
    NTT_gadget<FieldT> g(pb, input, output, true);

    g.generate_r1cs_constraints();

    for (size_t i = 0; i < vector_length; ++i)
        pb.val(input[i]) = FieldT::random_element();

    g.generate_r1cs_witness();

    pb.set_input_sizes(2*vector_length);
    assert(pb.is_satisfied());
   
    // For testing using Sage NTT
    // Make sure that both use the same 2nth root of unity
    /*
    std::cout << std::endl << "[" << pb.val(input[0]);
    for (size_t i = 1; i < vector_length; ++i) {
        std::cout  << "," << pb.val(input[i]);
    }
    std::cout << "]" << std::endl << "[" << pb.val(output[0]);
    for (size_t i = 1; i < vector_length; ++i) {
        std::cout << "," << pb.val(output[i]);
    }
    std::cout << "]" << std::endl;
    */

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_layer1_gadget(
    const size_t in_size, const size_t out_size, const size_t vector_length)
{
    protoboard<FieldT> pb;

    vector<pb_ciphertext<FieldT>> inputs, outputs;
    std::vector<std::vector<std::vector<FieldT>>> input_scalars;
    std::vector<std::vector<FieldT>> constant_term;
    
    for (size_t i = 0; i < in_size; ++i) {
        pb_ciphertext<FieldT> temp;
        temp.allocate(pb, 2, vector_length);
        inputs.emplace_back(temp);
    }
    for (size_t j = 0; j < out_size; ++j) {
        pb_ciphertext<FieldT> temp;
        temp.allocate(pb, 3, vector_length);
        outputs.emplace_back(temp);
        
        std::vector<std::vector<FieldT>> input_scalar_j;
        for (size_t i = 0; i < in_size; ++i) {
            std::vector<FieldT> input_scalar_ji(vector_length);
            for (size_t k = 0; k < vector_length; ++k)
                input_scalar_ji[k] = FieldT::random_element();
            input_scalar_j.emplace_back(input_scalar_ji);
        }
        input_scalars.emplace_back(input_scalar_j);

        std::vector<FieldT> constant_term_j(vector_length);
        for (size_t k = 0; k < vector_length; ++k)
            constant_term_j[k] = FieldT::random_element();
        constant_term.emplace_back(constant_term_j);
    }

    layer1_gadget<FieldT> g(pb);
    g.initialize(inputs, input_scalars, constant_term, outputs);

    g.generate_r1cs_constraints();
    
    for (size_t i = 0; i < in_size; ++i)
        for (size_t l = 0; l < 2; ++l)
            for (size_t k = 0; k < vector_length; ++k)
                pb.val(inputs[i][l][k]) = FieldT::random_element();

    g.generate_r1cs_witness();

    pb.set_input_sizes((in_size*2 + out_size*3)*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_layermid_ms_gadget(
        const size_t in_size, const size_t decomp_size, const size_t vector_length)
{
    protoboard<FieldT> pb;

    std::vector<pb_ciphertext<FieldT>> inputs, outputs;
    std::vector<std::vector<pb_variable_array<FieldT>>> decomps;
    std::vector<pb_variable_array<FieldT>> rlkkey0, rlkkey1;
    const FieldT pt_mod = FieldT(2);
    
    for (size_t i = 0; i < in_size; ++i) {
        pb_ciphertext<FieldT> tempi, tempo;
        tempi.allocate(pb, 2, vector_length);
        inputs.emplace_back(tempi);
        tempo.allocate(pb, 3, vector_length);
        outputs.emplace_back(tempo);

        std::vector<pb_variable_array<FieldT>> tempd;
        for (size_t j = 0; j < decomp_size; ++j) {
            pb_variable_array<FieldT> tempdd;
            tempdd.allocate(pb, vector_length);
            tempd.emplace_back(tempdd);
        }
        decomps.emplace_back(tempd);
    }

    for (size_t j = 0; j < decomp_size; ++j) {
        pb_variable_array<FieldT> tempr0, tempr1;
        tempr0.allocate(pb, vector_length);
        rlkkey0.emplace_back(tempr0);
        tempr1.allocate(pb, vector_length);
        rlkkey1.emplace_back(tempr1);
    }

    layermid_ms_gadget<FieldT> g(pb);
    g.initialize(inputs, decomps, rlkkey0, rlkkey1, pt_mod, outputs);

    g.generate_r1cs_constraints();
    
    for (size_t i = 0; i < in_size; ++i) {
        for (size_t l = 0; l < 2; ++l)
            for (size_t k = 0; k < vector_length; ++k)
                pb.val(inputs[i][l][k]) = FieldT::random_element();
        for (size_t j = 0; j < decomp_size; ++j)
            for (size_t k = 0; k < vector_length; ++k)
                pb.val(decomps[i][j][k]) = FieldT::random_element();
    }
    for (size_t j = 0; j < decomp_size; ++j) {
        for (size_t k = 0; k < vector_length; ++k) {
            pb.val(rlkkey0[j][k]) = FieldT::random_element();
            pb.val(rlkkey1[j][k]) = FieldT::random_element();
        }
    }

    g.generate_r1cs_witness();

    pb.set_input_sizes((in_size*5 + 2*decomp_size + in_size*decomp_size)*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}

template<typename FieldT>
r1cs_example<FieldT> test_layermid_gadget(
        const size_t in_size, const size_t out_size, const size_t decomp_size, const size_t vector_length)
{
    protoboard<FieldT> pb;

    std::vector<pb_ciphertext<FieldT>> inputs, outputs, to_removes;
    std::vector<std::vector<std::vector<FieldT>>> input_scalars;
    std::vector<std::vector<FieldT>> constant_term;
    std::vector<std::vector<pb_variable_array<FieldT>>> decomps;
    std::vector<pb_variable_array<FieldT>> rlkkey0, rlkkey1;
    const FieldT pt_mod = FieldT(2), q_toremove = FieldT::random_element();
    
    for (size_t i = 0; i < in_size; ++i) {
        pb_ciphertext<FieldT> tempi, tempt;
        tempi.allocate(pb, 2, vector_length);
        inputs.emplace_back(tempi);
        tempt.allocate(pb, 2, vector_length);
        to_removes.emplace_back(tempt);

        std::vector<pb_variable_array<FieldT>> tempd;
        for (size_t j = 0; j < decomp_size; ++j) {
            pb_variable_array<FieldT> tempdd;
            tempdd.allocate(pb, vector_length);
            tempd.emplace_back(tempdd);
        }
        decomps.emplace_back(tempd);
    }

    for (size_t j = 0; j < out_size; ++j) {
        pb_ciphertext<FieldT> tempo;
        tempo.allocate(pb, 3, vector_length);
        outputs.emplace_back(tempo);
        
        std::vector<std::vector<FieldT>> input_scalar_j;
        for (size_t i = 0; i < in_size; ++i) {
            std::vector<FieldT> input_scalar_ji(vector_length);
            for (size_t k = 0; k < vector_length; ++k)
                input_scalar_ji[k] = FieldT::random_element();
            input_scalar_j.emplace_back(input_scalar_ji);
        }
        input_scalars.emplace_back(input_scalar_j);

        std::vector<FieldT> constant_term_j(vector_length);
        for (size_t k = 0; k < vector_length; ++k)
            constant_term_j[k] = FieldT::random_element();
        constant_term.emplace_back(constant_term_j);
    }

    for (size_t j = 0; j < decomp_size; ++j) {
        pb_variable_array<FieldT> tempr0, tempr1;
        tempr0.allocate(pb, vector_length);
        rlkkey0.emplace_back(tempr0);
        tempr1.allocate(pb, vector_length);
        rlkkey1.emplace_back(tempr1);
    }

    layermid_gadget<FieldT> g(pb);
    g.initialize(
        inputs, input_scalars, constant_term,
        decomps, rlkkey0, rlkkey1, to_removes,
        pt_mod, q_toremove, outputs);

    g.generate_r1cs_constraints();
    
    for (size_t i = 0; i < in_size; ++i) {
        for (size_t l = 0; l < 2; ++l)
            for (size_t k = 0; k < vector_length; ++k) {
                pb.val(inputs[i][l][k]) = FieldT::random_element();
                pb.val(to_removes[i][l][k]) = FieldT::random_element();
            }
        for (size_t j = 0; j < decomp_size; ++j)
            for (size_t k = 0; k < vector_length; ++k)
                pb.val(decomps[i][j][k]) = FieldT::random_element();
    }
    for (size_t j = 0; j < decomp_size; ++j) {
        for (size_t k = 0; k < vector_length; ++k) {
            pb.val(rlkkey0[j][k]) = FieldT::random_element();
            pb.val(rlkkey1[j][k]) = FieldT::random_element();
        }
    }

    g.generate_r1cs_witness();

    pb.set_input_sizes((2*in_size*2 + out_size*3 + 2*decomp_size + in_size*decomp_size)*vector_length);
    assert(pb.is_satisfied());

    return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
}
