#include <iostream>

#include "identity_fake_gadget.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

using namespace libsnark;
using namespace std;

typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

int main(int argc, char *argv[]) {
    // Initialize the curve parameters.
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    protoboard<FieldT> pb;
    identity::identity_gadget<FieldT> g(pb, {110011, 220022, 330033});

    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(cs);

    while (true) {
        long long id_input;
        std::cin >> id_input;
        g.generate_r1cs_witness(id_input);

        // Generate proof
        auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
            keypair.pk, pb.primary_input(), pb.auxiliary_input());
        // Verify the proof
        bool is_valid =
            r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(
                keypair.vk, pb.primary_input(), proof);
        std::cout << "is_valid: " << is_valid << std::endl;
    }

    return 0;
}