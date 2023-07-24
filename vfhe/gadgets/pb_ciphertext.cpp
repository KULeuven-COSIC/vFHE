#ifndef PVC_PB_CIPHERTEXT
#define PVC_PB_CIPHERTEXT

#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

using namespace libsnark;

// New protoboard variable type that matches one RNS digit of a BGV ciphertext
template<typename FieldT>
class pb_ciphertext : private std::vector<pb_variable_array<FieldT>>
{
    typedef std::vector<pb_variable_array<FieldT> > contents;
public:
    using typename contents::iterator;
    using typename contents::const_iterator;
    using typename contents::reverse_iterator;
    using typename contents::const_reverse_iterator;

    using contents::begin;
    using contents::end;
    using contents::rbegin;
    using contents::rend;
    using contents::emplace_back;
    using contents::push_back;
    using contents::insert;
    using contents::reserve;
    using contents::size;
    using contents::empty;
    using contents::operator[];
    using contents::resize;

    pb_ciphertext() : contents() {};
    void allocate(protoboard<FieldT> &pb, size_t degree, const size_t n) {
        (*this).resize(degree);
        for (size_t j = 0; j < degree; ++j) {
            (*this)[j].allocate(pb, n);
        }
    };
};

#endif
