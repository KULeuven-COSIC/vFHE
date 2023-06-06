#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "pvc/gadgets/gadgets.cpp"

// Some consistency tests for gadgets

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
