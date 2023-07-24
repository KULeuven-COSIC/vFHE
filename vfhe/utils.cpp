#ifndef PVC_UTILS
#define PVC_UTILS

#include <vfhe/lattice_parameters.cpp>

// Struct that helps select the last type from a parameter pack
template <typename p, typename... ps>
struct last_from_pack {
    // fake parameter is needed to avoid "explicit specialization in non-namespace scope" error
    template <size_t s, typename fake = void> struct take {
        using type = typename last_from_pack<ps...>::template take<s-1>::type;
    };
    template <typename fake> struct take<1, fake> {
        using type = p;
    };
    using type = typename take<sizeof...(ps)+1>::type;
};

// tuple type where elements have types of parameter pack
template <typename... Ts>
using tuple_type_all = decltype(std::tuple_cat(std::declval<Ts>()...));

// tuple type where elements have types of parameter pack but T is excluded
template <typename T, typename... Ts>
using remove_t = tuple_type_all<
    typename std::conditional<std::is_same<T, Ts>::value, std::tuple<>, std::tuple<Ts>>::type...>;

// tuple type where elements have types of parameter pack but last type from pack is excluded
template <typename... Ts>
using tuple_type_exceptlast = remove_t<typename last_from_pack<Ts...>::type, Ts...>;

#endif
