#ifndef JNI_UTILS_H
#define JNI_UTILS_H

#include <jni.h>

#include <iostream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <sstream>
#include <vector>
typedef default_r1cs_gg_ppzksnark_pp ppT;

const char *G1_PATH = "cn/edu/zjucst/jni/G1";
const char *G2_PATH = "cn/edu/zjucst/jni/G2";

// Create a string from any type.
template <typename T>
std::string any_to_string(T t) {
    std::ostringstream out_str_stream;
    out_str_stream << t;
    return out_str_stream.str();
}

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
    static const char *field_strs[] = {"x0", "y0", "x1", "y1"};
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
                             r1cs_gg_ppzksnark_verification_key<ppT> &vk) {
    // Create a verifying-key object
    jclass vk_class = env->FindClass("cn/edu/zjucst/jni/VerifyingKey");
    if (vk_class == NULL) {
        return NULL;
    }
    jobject vk_object = env->AllocObject(vk_class);

    // TODO: alpha_g1
    jfieldID g1_vk_alpha_g1_fieldID =
        env->GetFieldID(vk_class, "alpha", "Lcn/edu/zjucst/jni/G1;");
    env->SetObjectField(vk_object, g1_vk_alpha_g1_fieldID,
                        create_g1(env, 11234234324, 12341234123));
    // TODO: beta_g2
    jfieldID g1_vk_beta_g2_fieldID =
        env->GetFieldID(vk_class, "beta", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(
        vk_object, g1_vk_beta_g2_fieldID,
        create_g2(env, 11234234324, 12341234123, 11234234324, 12341234123));

    // gamma_g2
    jfieldID vk_gamma_g2_fieldID =
        env->GetFieldID(vk_class, "gamma", "Lcn/edu/zjucst/jni/G2;");
    env->SetObjectField(
        vk_object, vk_gamma_g2_fieldID,
        create_g2(env, 11234234324, 12341234123, 11234234324, 12341234123));

    // delta_g2
    jfieldID vk_delta_g2_fieldID =
        env->GetFieldID(vk_class, "delta", "Lcn/edu/zjucst/jni/G2;");
    vk.delta_g2.to_affine_coordinates();
    env->SetObjectField(vk_object, vk_delta_g2_fieldID,
                        create_g2(env, vk.delta_g2.X.c0, vk.delta_g2.X.c1,
                                  vk.delta_g2.Y.c0, vk.delta_g2.Y.c1));
    
    // gamma_abc_g1
    jfieldID vk_gamma_abc_g1_fieldID =
        env->GetFieldID(vk_class, "gamma_abc", "[Lcn/edu/zjucst/jni/G1;");
    size_t size = vk.gamma_ABC_g1.size();
    jobjectArray gamma_abc_array = env->NewObjectArray(size, vk_class, NULL);

    const auto &now = vk.gamma_ABC_g1.first;
    for (size_t i = 0; i < size; i++) {
        

        // const auto &g1 = vk.gamma_ABC_g1[i];
        // env->SetObjectArrayElement(gamma_abc_array, i,
                                //    create_g1(env, vk.gamma_ABC_g1, 12341234123));
    }
    

    return vk_object;
}

// Create a proving key object from the libsnark proving key.
jobject create_proving_key(JNIEnv *env, r1cs_gg_ppzksnark_proving_key<ppT> &pk) {
    // Create a proving key object
    jobject pk_object =
        env->AllocObject(env->FindClass("cn/edu/zjucst/jni/ProvingKey"));
    if (pk_object == NULL) {
        return NULL;
    }

    // Create alpha G1 object
    jfieldID alpha_g1 =
        env->GetFieldID(env->FindClass("cn/edu/zjucst/jni/ProvingKey"), "alpha",
                        "Lcn/edu/zjucst/jni/G1;");
    pk.alpha_g1.to_affine_coordinates();
    env->SetObjectField(pk_object, alpha_g1,
                        create_g1(env, pk.alpha_g1.X, pk.alpha_g1.Y));

    // Create beta G1 object
    jfieldID beta_g1 =
        env->GetFieldID(env->FindClass("cn/edu/zjucst/jni/ProvingKey"),
                        "beta_g1", "Lcn/edu/zjucst/jni/G1;");
    pk.beta_g1.to_affine_coordinates();
    env->SetObjectField(pk_object, beta_g1,
                        create_g1(env, pk.beta_g1.X, pk.beta_g1.Y));

    // Create beta G2 object
    jfieldID beta_g2 =
        env->GetFieldID(env->FindClass("cn/edu/zjucst/jni/ProvingKey"),
                        "beta_g2", "Lcn/edu/zjucst/jni/G2;");
    pk.beta_g2.to_affine_coordinates();
    env->SetObjectField(pk_object, beta_g2,
                        create_g2(env, pk.beta_g2.X.c0, pk.beta_g2.X.c1,
                                  pk.beta_g2.Y.c0, pk.beta_g2.Y.c1));

    // Create delta G1 object
    jfieldID delta_g1 =
        env->GetFieldID(env->FindClass("cn/edu/zjucst/jni/ProvingKey"),
                        "delta_g1", "Lcn/edu/zjucst/jni/G1;");
    pk.delta_g1.to_affine_coordinates();
    env->SetObjectField(pk_object, delta_g1,
                        create_g1(env, pk.delta_g1.X, pk.delta_g1.Y));

    // Create delta G2 object
    jfieldID delta_g2 =
        env->GetFieldID(env->FindClass("cn/edu/zjucst/jni/ProvingKey"),
                        "delta_g2", "Lcn/edu/zjucst/jni/G2;");
    pk.delta_g2.to_affine_coordinates();
    env->SetObjectField(pk_object, delta_g2,
                        create_g2(env, pk.delta_g2.X.c0, pk.delta_g2.X.c1,
                                  pk.delta_g2.Y.c0, pk.delta_g2.Y.c1));

    return pk_object;
}

// Create a keypair from the libsnark keypair.
jobject create_keys(JNIEnv *env, r1cs_gg_ppzksnark_keypair<ppT> &keypair) {
    // Create a Key object
    jclass key_class = env->FindClass("cn/edu/zjucst/jni/Key");
    if (key_class == NULL) {
        return NULL;
    }
    jobject key_object = env->AllocObject(key_class);

    // Set the proving key
    jfieldID key_proving_key_fieldID = env->GetFieldID(
        key_class, "provingKey", "Lcn/edu/zjucst/jni/ProvingKey;");
    jobject key_proving_key_object = create_proving_key(env, keypair.pk);
    env->SetObjectField(key_object, key_proving_key_fieldID,
                        key_proving_key_object);

    // Set the verification key
    jfieldID key_verification_key_fieldID = env->GetFieldID(
        key_class, "verifyingKey", "Lcn/edu/zjucst/jni/VerifyingKey;");
    env->SetObjectField(key_object, key_verification_key_fieldID,
                        create_verifying_key(env, keypair.vk));

    return key_object;
}

// TODO: proof不用序列化字段
r1cs_gg_ppzksnark_proof<ppT> get_proof(JNIEnv *env, jobject proof_object) {
}

#endif