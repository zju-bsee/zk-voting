#include <iostream>

#include "identity_fake_gadget.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

using namespace libsnark;
using namespace std;

typedef default_r1cs_ppzksnark_pp ppT;
typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

int main(int argc, char* argv[]) {
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();

    protoboard<FieldT> pb;
    vector<long long> vec_voter_ids;
    for (int i = 0; i < 100; i++) {
        vec_voter_ids.push_back(i);
    }
    identity::identity_gadget<FieldT> g(pb, vec_voter_ids);

    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(cs);

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
    
    libff::bigint<128> a;
    stringstream ss;
    ss << "123804182308410238410238401238401823041823";
    ss >> a;
    std::cout << "a: " << a << std::endl;


    auto str = any_to_string(keypair.pk);
    istringstream in(str);
    r1cs_ppzksnark_proving_key<ppT> pk;
    in >> pk;
    std::cout << (pk == keypair.pk) << std::endl;

    std::cout << makeFq("3210923804182309841238410239841230841203841") << std::endl;

    return 0;
}