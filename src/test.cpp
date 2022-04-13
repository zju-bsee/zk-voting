#include <iostream>

#include "identity_fake_gadget.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

using namespace libsnark;
using namespace std;

typedef default_r1cs_ppzksnark_pp ppT;
typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

int main() {
    // Initialize the curve parameters.
    ppT::init_public_params();

    // Create a new protoboard.
    protoboard<FieldT> pb;
    vector<long long> vec_voter_ids;
    for (int i = 0; i < 5000; i++) {
        vec_voter_ids.push_back(i + 1);
    }
    identity::identity_gadget<FieldT> g(pb, vec_voter_ids);

    // Generate keys.
    std::cout << "==============================" << std::endl;
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

    long long id_input;
    std::cout << "Input your voter id to prove: ";
    std::cin >> id_input;
    g.generate_r1cs_witness(id_input);

    // Generate proof
    std::cout << "==============================" << std::endl;
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(),
                                            pb.auxiliary_input());

    // Verify the proof
    std::cout << "==============================" << std::endl;
    bool is_valid = r1cs_ppzksnark_verifier_strong_IC<ppT>(
        keypair.vk, pb.primary_input(), proof);
    std::cout << "is_valid: " << is_valid << std::endl;

    return 0;
}