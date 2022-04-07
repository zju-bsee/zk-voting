#ifndef JNI_TO_JAVA_HPP
#define JNI_TO_JAVA_HPP

#include <jni.h>

#include <iostream>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <sstream>
#include <vector>

#include "util.hpp"

namespace jni_to_java {
// Create a BigInteger object.
template <typename T>
jobject create_bigint(JNIEnv *env, T x) {
    // Parse the value to string
    jstring x_str = env->NewStringUTF(any_to_string(x).c_str());

    // Get the `public BigInteger(String val)` method id
    jclass bigint_class = env->FindClass("java/math/BigInteger");
    jmethodID bigint_init =
        env->GetMethodID(bigint_class, "<init>", "(Ljava/lang/String;)V");

    // Allocate a bigint and return
    return env->NewObject(bigint_class, bigint_init, x_str);
}

// Create a G1 point object with given (x, y).
template <typename T>
jobject create_g1(JNIEnv *env, T x, T y) {
    jobject bigint_x = create_bigint(env, x);
    jobject bigint_y = create_bigint(env, y);

    jclass g1_class = env->FindClass(G1_PATH);
    if (g1_class == NULL) {
        return NULL;
    }
    jobject g1_object = env->AllocObject(g1_class);

    jfieldID g1x_fieldID =
        env->GetFieldID(g1_class, "x", "Ljava/math/BigInteger;");
    env->SetObjectField(g1_object, g1x_fieldID, bigint_x);
    jfieldID g1y_fieldID =
        env->GetFieldID(g1_class, "y", "Ljava/math/BigInteger;");
    env->SetObjectField(g1_object, g1y_fieldID, bigint_y);

    return g1_object;
}

// Create a G2 point object with given ((x0, x1), (y0, y1)).
template <typename T>
jobject create_g2(JNIEnv *env, T x0, T x1, T y0, T y1) {
    static const char *field_strs[] = {"x0", "x1", "y0", "y1"};
    T values[4] = {x0, x1, y0, y1};

    // Create four bigints
    auto objects = std::vector<jobject>(4);
    for (int i = 0; i < 4; i++) {
        objects[i] = create_bigint(env, values[i]);
    }

    // Create a G2 object
    jclass g2_class = env->FindClass(G2_PATH);
    if (g2_class == NULL) {
        return NULL;
    }
    jobject g2_object = env->AllocObject(g2_class);

    // Set the object fields
    for (int i = 0; i < 4; i++) {
        jfieldID fieldID =
            env->GetFieldID(g2_class, field_strs[i], "Ljava/math/BigInteger;");
        env->SetObjectField(g2_object, fieldID, objects[i]);
    }

    return g2_object;
}

// Create a VerifyingKey object from the libsnark verification key.
jobject create_verifying_key(JNIEnv *env,
                             const r1cs_ppzksnark_verification_key<ppT> &vk) {
    // Create a verifying-key object
    jclass vk_class = env->FindClass("cn/edu/zjucst/jni/VerifyingKey");
    if (vk_class == NULL) {
        return NULL;
    }
    jobject vk_object = env->AllocObject(vk_class);

    // G2 a
    auto a = libff::G2<ppT>(vk.alphaA_g2);
    a.to_affine_coordinates();
    jobject g2_a = create_g2(env, a.X.c0, a.X.c1, a.Y.c0, a.Y.c1);
    jfieldID a_fieldID =
        env->GetFieldID(vk_class, "a", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(vk_object, a_fieldID, g2_a);

    // G1 b
    auto b = libff::G1<ppT>(vk.alphaB_g1);
    b.to_affine_coordinates();
    jobject g1_b = create_g1(env, b.X, b.Y);
    jfieldID b_fieldID =
        env->GetFieldID(vk_class, "b", "Lcn/edu/zjucst/jni/G1;");
    env->SetObjectField(vk_object, b_fieldID, g1_b);

    // G2 c
    auto c = libff::G2<ppT>(vk.alphaC_g2);
    c.to_affine_coordinates();
    jobject g2_c = create_g2(env, c.X.c0, c.X.c1, c.Y.c0, c.Y.c1);
    jfieldID c_fieldID =
        env->GetFieldID(vk_class, "c", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(vk_object, c_fieldID, g2_c);

    // G2 gamma
    auto gamma = libff::G2<ppT>(vk.gamma_g2);
    gamma.to_affine_coordinates();
    jobject g2_gamma =
        create_g2(env, gamma.X.c0, gamma.X.c1, gamma.Y.c0, gamma.Y.c1);
    jfieldID gamma_fieldID =
        env->GetFieldID(vk_class, "gamma", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(vk_object, gamma_fieldID, g2_gamma);

    // G1 gamma_beta_1
    auto gamma_beta_1 = libff::G1<ppT>(vk.gamma_beta_g1);
    gamma_beta_1.to_affine_coordinates();
    jobject g1_gamma_beta_1 = create_g1(env, gamma_beta_1.X, gamma_beta_1.Y);
    jfieldID gamma_beta_1_fieldID =
        env->GetFieldID(vk_class, "gamma_beta_1", "Lcn/edu/zjucst/jni/G1;");
    env->SetObjectField(vk_object, gamma_beta_1_fieldID, g1_gamma_beta_1);

    // G2 gamma_beta_2
    auto gamma_beta_2 = libff::G2<ppT>(vk.gamma_beta_g2);
    gamma_beta_2.to_affine_coordinates();
    jobject g2_gamma_beta_2 =
        create_g2(env, gamma_beta_2.X.c0, gamma_beta_2.X.c1, gamma_beta_2.Y.c0,
                  gamma_beta_2.Y.c1);
    jfieldID gamma_beta_2_fieldID =
        env->GetFieldID(vk_class, "gamma_beta_2", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(vk_object, gamma_beta_2_fieldID, g2_gamma_beta_2);

    // G2 z
    auto z = libff::G2<ppT>(vk.rC_Z_g2);
    z.to_affine_coordinates();
    jobject g2_z = create_g2(env, z.X.c0, z.X.c1, z.Y.c0, z.Y.c1);
    jfieldID z_fieldID =
        env->GetFieldID(vk_class, "z", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(vk_object, z_fieldID, g2_z);

    // G1[] ic
    jclass g1_class = env->FindClass("cn/edu/zjucst/jni/G1");
    if (g1_class == NULL) {
        return NULL;
    }
    // TODO: Is it wrong?
    jobjectArray ic_array =
        env->NewObjectArray(1 + vk.encoded_IC_query.size(), g1_class, NULL);

    accumulation_vector<G1<ppT>> IC(vk.encoded_IC_query);
    G1<ppT> IC_0(IC.first);
    IC_0.to_affine_coordinates();
    jobject ic_0 = create_g1(env, IC_0.X, IC_0.Y);
    env->SetObjectArrayElement(ic_array, 0, ic_0);
    for (size_t i = 0; i < IC.size(); i++) {
        G1<ppT> IC_N(IC.rest[i]);
        IC_N.to_affine_coordinates();
        jobject ic_N = create_g1(env, IC_N.X, IC_N.Y);
        env->SetObjectArrayElement(ic_array, i + 1, ic_N);
    }
    jfieldID ic_fieldID =
        env->GetFieldID(vk_class, "ic", "[Lcn/edu/zjucst/jni/G1;");
    env->SetObjectField(vk_object, ic_fieldID, ic_array);

    return vk_object;
}

// Create a keypair from the libsnark keypair.
jobject create_key(JNIEnv *env, const r1cs_ppzksnark_keypair<ppT> &keypair) {
    // Create a Key object.
    jclass key_class = env->FindClass("cn/edu/zjucst/jni/Key");
    if (key_class == NULL) {
        return NULL;
    }
    jobject key_object = env->AllocObject(key_class);

    // Create a verifying key object.
    jobject vk_object = create_verifying_key(env, keypair.vk);
    jfieldID vk_fieldID = env->GetFieldID(key_class, "verifyingKey",
                                          "Lcn/edu/zjucst/jni/VerifyingKey;");
    env->SetObjectField(key_object, vk_fieldID, vk_object);

    // Create proving key bytes array.
    std::string pk_bytes_str = any_to_string(keypair.pk);
    jbyteArray pk_bytes = env->NewByteArray(pk_bytes_str.size());
    env->SetByteArrayRegion(pk_bytes, 0, pk_bytes_str.size(),
                            (jbyte *)pk_bytes_str.c_str());
    jfieldID pk_bytes_fieldID =
        env->GetFieldID(key_class, "provingKeyBytes", "[B");
    env->SetObjectField(key_object, pk_bytes_fieldID, pk_bytes);

    // Create verifying key bytes array.
    std::string vk_bytes_str = any_to_string(keypair.vk);
    jbyteArray vk_bytes = env->NewByteArray(vk_bytes_str.size());
    env->SetByteArrayRegion(
        vk_bytes, 0, vk_bytes_str.size(),
        reinterpret_cast<const jbyte *>(vk_bytes_str.c_str()));
    jfieldID vk_bytes_fieldID =
        env->GetFieldID(key_class, "verifyingKeyBytes", "[B");
    env->SetObjectField(key_object, vk_bytes_fieldID, vk_bytes);

    return key_object;
}

// Create java Proof.
jobject create_proof(JNIEnv *env, r1cs_ppzksnark_proof<ppT> proof) {
    // Create a Proof object.
    jclass proof_class = env->FindClass("cn/edu/zjucst/jni/Proof");
    if (proof_class == NULL) {
        return NULL;
    }
    jobject proof_object = env->AllocObject(proof_class);

    // Get the G1 and G2's classes.
    jclass g1_class = env->FindClass("cn/edu/zjucst/jni/G1");
    if (g1_class == NULL) {
        return NULL;
    }
    jclass g2_class = env->FindClass("cn/edu/zjucst/jni/G2");
    if (g2_class == NULL) {
        return NULL;
    }

    // A
    auto a = libff::G1<ppT>(proof.g_A.g);
    a.to_affine_coordinates();
    jobject g1_a = create_g1(env, a.X, a.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "a", "Lcn/edu/zjucst/jni/G1;"), g1_a);

    // A_p
    auto a_p = libff::G1<ppT>(proof.g_A.h);
    a_p.to_affine_coordinates();
    jobject g1_a_p = create_g1(env, a_p.X, a_p.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "a_p", "Lcn/edu/zjucst/jni/G1;"), g1_a_p);

    // B
    auto b = libff::G2<ppT>(proof.g_B.g);
    b.to_affine_coordinates();
    jobject g2_b = create_g2(env, b.X.c0, b.X.c1, b.Y.c0, b.Y.c1);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "b", "Lcn/edu/zjucst/jni/G2;"), g2_b);

    // B_p
    auto b_p = libff::G1<ppT>(proof.g_B.h);
    b_p.to_affine_coordinates();
    jobject g1_b_p = create_g1(env, b_p.X, b_p.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "b_p", "Lcn/edu/zjucst/jni/G1;"), g1_b_p);

    // C
    auto c = libff::G1<ppT>(proof.g_C.g);
    c.to_affine_coordinates();
    jobject g1_c = create_g1(env, c.X, c.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "c", "Lcn/edu/zjucst/jni/G1;"), g1_c);

    // C_p
    auto c_p = libff::G1<ppT>(proof.g_C.h);
    c_p.to_affine_coordinates();
    jobject g1_c_p = create_g1(env, c_p.X, c_p.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "c_p", "Lcn/edu/zjucst/jni/G1;"), g1_c_p);

    // H
    auto h = libff::G1<ppT>(proof.g_H);
    h.to_affine_coordinates();
    jobject g1_h = create_g1(env, h.X, h.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "h", "Lcn/edu/zjucst/jni/G1;"), g1_h);

    // K
    auto k = libff::G1<ppT>(proof.g_K);
    k.to_affine_coordinates();
    jobject g1_k = create_g1(env, k.X, k.Y);
    env->SetObjectField(
        proof_object,
        env->GetFieldID(proof_class, "k", "Lcn/edu/zjucst/jni/G1;"), g1_k);

    return proof_object;
}
}  // namespace jni_to_java

#endif