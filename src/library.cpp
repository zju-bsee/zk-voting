#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "cn_edu_zjucst_jni_ZKVotingJNI.h"
#include "identity_fake_gadget.hpp"
#include "jni_utils.h"
#include "util.hpp"

using namespace libsnark;
using namespace std;

// 这个文件是JNI调用入口

// Default curve for G16.
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

/*
 * Class:     cn_edu_zjucst_jni_ZKVotingJNI
 * Method:    generateVoterKeys
 * Signature: (I)Lcn/edu/zjucst/jni/Key;
 */
JNIEXPORT jobject JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_generateVoterKeys(
    JNIEnv* env, jclass this_class, jint voter_count) {
    // Initialize the curve parameters.
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // Create a protoboard for variables.
    protoboard<FieldT> pb;
    identity::identity_gadget<FieldT> g(pb, voter_count);
    g.generate_r1cs_constraints();

    auto cs = pb.get_constraint_system();
    auto keypair =
        r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(cs);

    return jni_utils::create_keys(env, keypair);
}

/*
 * Class:     cn_edu_zjucst_jni_ZKVotingJNI
 * Method:    verifyVoterProof
 * Signature: (Lcn/edu/zjucst/jni/Proof;)Z
 */
JNIEXPORT jboolean JNICALL
Java_cn_edu_zjucst_jni_ZKVotingJNI_verifyVoterProof(JNIEnv* env, jobject this_object, jobject proof_object) {
    // Initialize the curve parameters.
    // default_r1cs_gg_ppzksnark_pp::init_public_params();

    // Get the proof from the Java object.
    // auto proof = get_proof(env, proof_object);

    return false;
}