#ifndef UTIL_H
#define UTIL_H

#include <fstream>

#include "libff/algebra/curves/public_params.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

using namespace libsnark;
using namespace libff;

typedef default_r1cs_ppzksnark_pp ppT;

template <typename T>
libff::G1<ppT> CopyG1(T x, T y) {
    auto g1 = libff::G1<ppT>();
    g1.X = x;
    g1.Y = y;
    g1.Z = libff::alt_bn128_Fq::one();
    return g1;
}

template <typename T>
libff::G2<ppT> CopyG2(T x0, T x1, T y0, T y1) {
    auto g2 = libff::G2<ppT>();
    g2.X.c0 = x0;
    g2.X.c1 = x1;
    g2.Y.c0 = y0;
    g2.Y.c1 = y1;
    g2.Z = libff::alt_bn128_Fq2::one();
    return g2;
}

// Create a string from any type.
template <typename T>
std::string any_to_string(T t) {
    std::ostringstream out_str_stream;
    out_str_stream << t;
    std::flush(out_str_stream);
    return out_str_stream.str();
}

void serialize_G1(libff::G1<ppT> g1, std::ostream &out) {
    g1.to_affine_coordinates();

    out << "[" << g1.X << "," << g1.Y << "]";
}

void serialize_G2(libff::G2<ppT> g2, std::ostream &out) {
    g2.to_affine_coordinates();

    out << "[[" << g2.X.c0 << "," << g2.X.c1 << "],";
    out << "[" << g2.Y.c0 << "," << g2.Y.c1 << "]]";
}

libff::alt_bn128_Fq makeFq(const std::string &s) {
    libff::bigint<libff::alt_bn128_q_limbs> a;
    std::stringstream ss;
    ss << s;
    ss >> a;
    return libff::alt_bn128_Fq(a);
}

libff::G1<ppT> g1_from_string(const std::string &x, const std::string &y) {
    libff::G1<ppT> tmp;
    tmp.X = makeFq(x);
    tmp.Y = makeFq(y);
    tmp.Z = libff::alt_bn128_Fq::one();

    return tmp;
}

libff::G2<ppT> g2_from_string(const std::string &x0, const std::string &x1,
                              const std::string &y0, const std::string &y1) {
    libff::G2<ppT> tmp;
    tmp.X.c0 = makeFq(x0);
    tmp.X.c1 = makeFq(x1);
    tmp.Y.c0 = makeFq(y0);
    tmp.Y.c1 = makeFq(y1);
    tmp.Z = libff::alt_bn128_Fq2::one();

    return tmp;
}

template <typename T>
libff::G1<default_r1cs_ppzksnark_pp> deserialize_G1(T x, T y) {
    auto g1 = libff::G1<default_r1cs_ppzksnark_pp>();
    g1.X = x;
    g1.Y = y;

    // ...
    g1.Z = libff::alt_bn128_Fq::one();

    std::stringstream ss;
    ss << g1;
    ss >> g1;
    return g1;
}

template <typename T>
libff::G2<default_r1cs_ppzksnark_pp> deserialize_G2(T x0, T x1, T y0, T y1) {
    auto g2 = libff::G2<default_r1cs_ppzksnark_pp>();

    g2.X.c0 = x0;
    g2.X.c1 = x1;
    g2.Y.c0 = y0;
    g2.Y.c1 = y1;
    g2.Z = libff::alt_bn128_Fq2::one();

    std::stringstream ss;
    ss << g2;
    ss >> g2;

    return g2;
}

template <typename T1, typename T2>
knowledge_commitment<T1, T2> deserialize_knowledge_commitment(T1 x, T2 y) {
    knowledge_commitment<T1, T2> kc;
    kc.g = x;
    kc.h = y;
    return kc;
}

template <typename ppT>
void print_vk_to_file(r1cs_ppzksnark_verification_key<ppT> vk,
                      std::string pathToFile) {
    std::ofstream vk_data;
    vk_data.open(pathToFile);

    libff::G2<ppT> A(vk.alphaA_g2);
    A.to_affine_coordinates();
    vk_data << "[[\"" << A.X.c0 << "\",\"" << A.X.c1 << "\"],";
    vk_data << "[\"" << A.Y.c0 << "\",\"" << A.Y.c1 << "\"]]" << std::endl;

    G1<ppT> B(vk.alphaB_g1);
    B.to_affine_coordinates();
    vk_data << "[\"" << B.X << "\",\"" << B.Y << "\"]" << std::endl;

    libff::G2<ppT> C(vk.alphaC_g2);
    C.to_affine_coordinates();
    vk_data << "[[\"" << C.X.c0 << "\",\"" << C.X.c1 << "\"],";
    vk_data << "[\"" << C.Y.c0 << "\",\"" << C.Y.c1 << "\"]]" << std::endl;

    std::cout << "gamma" << std::endl;
    libff::G2<ppT> gamma(vk.gamma_g2);
    gamma.to_affine_coordinates();
    vk_data << "[[\"" << gamma.X.c0 << "\",\"" << gamma.X.c1 << "\"],";
    vk_data << "[\"" << gamma.Y.c0 << "\",\"" << gamma.Y.c1 << "\"]]"
            << std::endl;

    std::cout << "gamma_beta_1" << std::endl;
    G1<ppT> gamma_beta_1(vk.gamma_beta_g1);
    gamma_beta_1.to_affine_coordinates();
    vk_data << "[\"" << gamma_beta_1.X << "\",\"" << gamma_beta_1.Y << "\"]"
            << std::endl;

    std::cout << "gamma_beta_2" << std::endl;
    libff::G2<ppT> gamma_beta_2(vk.gamma_beta_g2);
    gamma_beta_2.to_affine_coordinates();
    vk_data << "[[\"" << gamma_beta_2.X.c0 << "\",\"" << gamma_beta_2.X.c1
            << "\"],";
    vk_data << "[\"" << gamma_beta_2.Y.c0 << "\",\"" << gamma_beta_2.Y.c1
            << "\"]]" << std::endl;

    std::cout << "Z" << std::endl;
    libff::G2<ppT> Z(vk.rC_Z_g2);
    Z.to_affine_coordinates();
    vk_data << "[[\"" << Z.X.c0 << "\",\"" << Z.X.c1 << "\"],";
    vk_data << "[\"" << Z.Y.c0 << "\",\"" << Z.Y.c1 << "\"]]" << std::endl;

    std::cout << "IC" << std::endl;
    accumulation_vector<G1<ppT>> IC(vk.encoded_IC_query);
    G1<ppT> IC_0(IC.first);
    IC_0.to_affine_coordinates();
    vk_data << "[\"" << IC_0.X << "\",\"" << IC_0.Y << "\"]" << std::endl;

    std::cout << "IC.size: " << IC.size() << std::endl;
    for (size_t i = 0; i < IC.size(); i++) {
        G1<ppT> IC_N(IC.rest[i]);
        IC_N.to_affine_coordinates();
        vk_data << "[\"" << IC_N.X << "\",\"" << IC_N.Y << "\"]" << std::endl;
    }

    vk_data.close();
}

template <typename ppT>
void print_proof_to_file(r1cs_ppzksnark_proof<ppT> proof,
                         std::string pathToFile) {
    std::ofstream proof_data;
    proof_data.open(pathToFile);

    G1<ppT> A_g(proof.g_A.g);
    A_g.to_affine_coordinates();
    proof_data << "[\"" << A_g.X << "\",\"" << A_g.Y << "\"]" << std::endl;

    G1<ppT> A_h(proof.g_A.h);
    A_h.to_affine_coordinates();
    proof_data << "[\"" << A_h.X << "\",\"" << A_h.Y << "\"]" << std::endl;

    G2<ppT> B_g(proof.g_B.g);
    B_g.to_affine_coordinates();
    proof_data << "[[\"" << B_g.X.c0 << "\",\"" << B_g.X.c1 << "\"],"
               << "[\"" << B_g.Y.c0 << "\",\"" << B_g.Y.c1 << "\"]]"
               << std::endl;

    G1<ppT> B_h(proof.g_B.h);
    B_h.to_affine_coordinates();
    proof_data << "[\"" << B_h.X << "\",\"" << B_h.Y << "\"]" << std::endl;

    G1<ppT> C_g(proof.g_C.g);
    C_g.to_affine_coordinates();
    proof_data << "[\"" << C_g.X << "\",\"" << C_g.Y << "\"]" << std::endl;

    G1<ppT> C_h(proof.g_C.h);
    C_h.to_affine_coordinates();
    proof_data << "[\"" << C_h.X << "\",\"" << C_h.Y << "\"]" << std::endl;

    G1<ppT> H(proof.g_H);
    H.to_affine_coordinates();
    proof_data << "[\"" << H.X << "\",\"" << H.Y << "\"]" << std::endl;

    G1<ppT> K(proof.g_K);
    K.to_affine_coordinates();
    proof_data << "[\"" << K.X << "\",\"" << K.Y << "\"]" << std::endl;

    proof_data.close();
}
#endif