#ifndef UTIL_H
#define UTIL_H

#include <fstream>

#include "libff/algebra/curves/public_params.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

// Verify G16 proof.
template <typename ppT, typename FieldT>
bool verify_proof(
    const r1cs_gg_ppzksnark_verification_key<ppT> verification_key,
    const r1cs_primary_input<FieldT> primary_input,
    const r1cs_gg_ppzksnark_proof<ppT> proof) {
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(verification_key,
                                                     primary_input, proof);
}

// Generate G16 proof.
template <typename ppT, typename FieldT>
r1cs_gg_ppzksnark_proof<ppT> prove(
    r1cs_gg_ppzksnark_proving_key<ppT> pk,
    r1cs_primary_input<FieldT> primary_input,
    r1cs_auxiliary_input<FieldT> auxiliary_input) {
    return r1cs_gg_ppzksnark_prover<ppT>(pk, primary_input, auxiliary_input);
}

// Serialize G16 proving key.
template <typename ppT>
void serialize_pk(r1cs_gg_ppzksnark_proving_key<ppT> pk, string pathToFile) {
    ofstream pk_data;
    pk_data.open(pathToFile);

    pk_data << pk;
    pk_data.close();
}

// Serialize G16 verifying key.
template <typename ppT>
void serialize_vk(r1cs_gg_ppzksnark_verification_key<ppT> vk,
                  string pathToFile) {
    ofstream vk_data;
    vk_data.open(pathToFile);

    vk_data << vk;
    vk_data.close();
}

// Serialize G16 proof.
template <typename ppT>
void serialize_proof(r1cs_gg_ppzksnark_proof<ppT> proof, string pathToFile) {
    ofstream proof_data;
    proof_data.open(pathToFile);

    proof_data << proof;
    proof_data.close();
}
#endif