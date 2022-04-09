#include <fcntl.h>
#include <unistd.h>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "cn_edu_zjucst_jni_ZKVotingJNI.h"
#include "identity_fake_gadget.hpp"
#include "jni_from_java.hpp"
#include "jni_to_java.hpp"
#include "util.hpp"

using namespace libsnark;
using namespace std;

typedef default_r1cs_ppzksnark_pp ppT;
typedef libff::Fr<ppT> FieldT;

void initialize() {
    ppT::init_public_params();

    // Disable zksnark output.
    close(STDOUT_FILENO);
    open("/dev/null", O_WRONLY);
}

// Generate a new key pair by the given voter_ids.
JNIEXPORT jobject JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_generateVoterKeys(
    JNIEnv* env, jclass this_class, jobjectArray voter_ids) {
    if (voter_ids == NULL) {
        return NULL;
    }

    // Initialize the curve parameters.
    ppT::init_public_params();

    // Parse jobject array to vector<long long>.
    auto vec_voter_ids = jni_from_java::jstring_array_to_nums(env, voter_ids);
    if (vec_voter_ids.size() <= 1) {
        return NULL;
    }

    // Construct protoboard.
    protoboard<FieldT> pb;
    identity::identity_gadget<FieldT> g(pb, vec_voter_ids);
    const auto cs = pb.get_constraint_system();
    const auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
    return jni_to_java::create_key(env, keypair);
}

// Verify the proof by the given voter_id and proof.
JNIEXPORT jboolean JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_verifyVoterProof(
    JNIEnv* env, jclass this_class, jobject jproof, jobject jvk) {
    if (jproof == NULL || jvk == NULL) {
        return false;
    }

    // Initialize the curve parameters.
    ppT::init_public_params();

    // Parse proof.
    auto proof = jni_from_java::parse_proof(env, jproof);
    print_proof_to_file(proof, "thisProof.txt");

    auto vk = jni_from_java::parse_verifying_key(env, jvk);
    print_vk_to_file(vk, "thisVk.txt");

    // Verify the proof.
    r1cs_ppzksnark_primary_input<ppT> inputs;
    return r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, inputs, proof);

    return false;
}

// Generate a proof for the voter.
JNIEXPORT jobject JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_generateVoterProof(
    JNIEnv* env, jclass this_class, jbyteArray jpk_bytes, jobject jbigint_id,
    jobjectArray jvoter_ids) {
    if (jpk_bytes == NULL || jbigint_id == NULL || jvoter_ids == NULL) {
        return NULL;
    }

    // Initialize the curve parameters.
    ppT::init_public_params();

    // Parse the proving key.
    auto pk = jni_from_java::parse_proving_key(env, jpk_bytes);
    
    // Parse the voter ids.
    auto id = jni_from_java::parse_bigint(env, jbigint_id);
    auto voterIDs = jni_from_java::jstring_array_to_nums(env, jvoter_ids);

    // Construct the proof.
    protoboard<FieldT> pb;
    identity::identity_gadget<FieldT> g(pb, voterIDs);
    g.generate_r1cs_witness(id);
    const auto proof = r1cs_ppzksnark_prover<ppT>(pk, pb.primary_input(),
                                                  pb.auxiliary_input());

    return jni_to_java::create_proof(env, proof);
}