#include "identity_fake_gadget.hpp"
#include "util.hpp"
#include "cn_edu_zjucst_jni_ZKVotingJNI.h"

using namespace libsnark;
using namespace std;

// Default curve for G16.
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

/*
 * Class:     cn_edu_zjucst_jni_ZKVotingJNI
 * Method:    hello
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_hello
  (JNIEnv *, jclass, jint x) {
    return x;
  }

// int main() {
//     // Initialize the curve parameters.
//     default_r1cs_gg_ppzksnark_pp::init_public_params();

//     protoboard<FieldT> pb;
//     identity_gadget<FieldT> g(pb, 6);
//     g.generate_r1cs_constraints();
//     auto cs = pb.get_constraint_system();
//     auto keypair =
//         r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(cs);
//     std::cout << cs.primary_input_size << ' ' << cs.auxiliary_input_size
//               << std::endl;

//     // Testing public inputs
//     r1cs_primary_input<FieldT> primary_input;
//     vector<int> voters = {1, 2, 3, 4, 5, 6};
//     primary_input.insert(primary_input.end(), voters.begin(), voters.end());
//     for (auto i : primary_input) {
//         std::cout << i << std::endl;
//     }

//     while (true) {
//         r1cs_auxiliary_input<FieldT> auxiliary_input;
//         int input_id;
//         cin >> input_id;

//         protoboard<FieldT> pb;
//         identity_gadget<FieldT> g(pb, 6);
//         g.generate_r1cs_constraints();
//         g.generate_r1cs_witness(input_id, voters);

//         // auto apb = pb;

//         // auxiliary_input.push_back(input_id);

//         auto proof = prove<default_r1cs_gg_ppzksnark_pp>(
//             keypair.pk, pb.primary_input(), pb.auxiliary_input());
//         std::cout << verify<default_r1cs_gg_ppzksnark_pp>(keypair.vk,
//                                                           primary_input, proof)
//                   << std::endl;

//         stringstream ss;

//         proof.g_A.to_affine_coordinates();
//         proof.g_B.to_affine_coordinates();
//         proof.g_C.to_affine_coordinates();

//         std::cout << proof.g_A.X << std::endl;
//         std::cout << proof.g_A.Y << std::endl;
//         std::cout << proof.g_B.X << std::endl;
//         std::cout << proof.g_B.X.c0 << ' ' << proof.g_B.X.c1 << std::endl;
//         std::cout << proof.g_B.Y.c0 << ' ' << proof.g_B.Y.c1 << std::endl;
//         std::cout << proof.g_B.Y << std::endl;
//         std::cout << proof.g_C.X << std::endl;
//         std::cout << proof.g_C.Y << std::endl;
//         // std::cout << keypair.pk << std::endl;
//         // std::cout << keypair.vk << std::endl;
//     }

//     return 0;
// }