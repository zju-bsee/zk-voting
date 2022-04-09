#ifndef JNI_FROM_JAVA_HPP
#define JNI_FROM_JAVA_HPP

#include <jni.h>

#include <iostream>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <sstream>
#include <vector>

typedef default_r1cs_ppzksnark_pp ppT;

const char *G1_PATH = "cn/edu/zjucst/jni/G1";
const char *G2_PATH = "cn/edu/zjucst/jni/G2";

namespace jni_from_java {
// Create a vector<long long> from a jString objectArray.
std::vector<long long> jstring_array_to_nums(JNIEnv *env,
                                             jobjectArray strings) {
    std::vector<long long> vec_long_long;
    if (strings == NULL) {
        return vec_long_long;
    }

    jsize len = env->GetArrayLength(strings);
    for (int i = 0; i < len; ++i) {
        jstring jstr = (jstring)env->GetObjectArrayElement(strings, i);
        const char *cstr = env->GetStringUTFChars(jstr, NULL);
        vec_long_long.push_back(std::stoll(cstr));
    }
    return vec_long_long;
}

// Create a string from a jstring.
std::string jbytes_to_string(JNIEnv *env, jbyteArray bytes) {
    jsize len = env->GetArrayLength(bytes);
    jbyte *body = env->GetByteArrayElements(bytes, NULL);
    std::string str(reinterpret_cast<char *>(body), len);
    env->ReleaseByteArrayElements(bytes, body, 0);
    return str;
}

// Create a ProvingKey object from java bytes array.
r1cs_ppzksnark_proving_key<ppT> parse_proving_key(JNIEnv *env,
                                                  jbyteArray jpk_bytes) {
    std::istringstream ss(jbytes_to_string(env, jpk_bytes));
    r1cs_ppzksnark_proving_key<ppT> pk;
    ss >> pk;

    return pk;
}

// Extract a field from G1/G2 java object.
std::string parse_g(JNIEnv *env, jobject jG_obj, jclass jG_class,
                    const char *field_name) {
    jfieldID field =
        env->GetFieldID(jG_class, field_name, "Ljava/math/BigInteger;");
    jobject jG = env->GetObjectField(jG_obj, field);
    jmethodID toString_id =
        env->GetMethodID(env->FindClass("java/math/BigInteger"), "toString",
                         "()Ljava/lang/String;");

    jobject jG_sstr = env->CallObjectMethod(jG, toString_id);
    const char *cstr = env->GetStringUTFChars((jstring)jG_sstr, NULL);
    return std::string(cstr);
}

// Parse G1 jobject to a G1 value.
libff::G1<ppT> parse_g1(JNIEnv *env, jobject jG1_obj) {
    jclass G1_class = env->GetObjectClass(jG1_obj);

    const auto x = parse_g(env, jG1_obj, G1_class, "x");
    const auto y = parse_g(env, jG1_obj, G1_class, "y");

    return g1_from_string(x, y);
}

// Parse G2 jobject to a G2 value.
libff::G2<ppT> parse_g2(JNIEnv *env, jobject jG2_obj) {
    jclass G2_class = env->GetObjectClass(jG2_obj);

    const auto x0 = parse_g(env, jG2_obj, G2_class, "x0");
    const auto x1 = parse_g(env, jG2_obj, G2_class, "x1");
    const auto y0 = parse_g(env, jG2_obj, G2_class, "y0");
    const auto y1 = parse_g(env, jG2_obj, G2_class, "y1");

    return g2_from_string(x0, x1, y0, y1);
}

r1cs_ppzksnark_verification_key<ppT> parse_verifying_key(JNIEnv *env,
                                                         jobject jvk) {
    jclass cls = env->GetObjectClass(jvk);
    
    // G2 a
    jfieldID a_field = env->GetFieldID(cls, "a", "Lcn/edu/zjucst/jni/G2;");
    jobject a_obj = env->GetObjectField(jvk, a_field);
    libff::G2<ppT> a = parse_g2(env, a_obj);

    // G1 b
    jfieldID b_field = env->GetFieldID(cls, "b", "Lcn/edu/zjucst/jni/G1;");
    jobject b_obj = env->GetObjectField(jvk, b_field);
    libff::G1<ppT> b = parse_g1(env, b_obj);

    // G2 c
    jfieldID c_field = env->GetFieldID(cls, "c", "Lcn/edu/zjucst/jni/G2;");
    jobject c_obj = env->GetObjectField(jvk, c_field);
    libff::G2<ppT> c = parse_g2(env, c_obj);

    // G2 gamma
    jfieldID gamma_field = env->GetFieldID(cls, "gamma", "Lcn/edu/zjucst/jni/G2;");
    jobject gamma_obj = env->GetObjectField(jvk, gamma_field);
    libff::G2<ppT> gamma = parse_g2(env, gamma_obj);

    // G1 gamma_beta_1
    jfieldID gamma_beta_1_field =
        env->GetFieldID(cls, "gamma_beta_1", "Lcn/edu/zjucst/jni/G1;");
    jobject gamma_beta_1_obj = env->GetObjectField(jvk, gamma_beta_1_field);
    libff::G1<ppT> gamma_beta_1 = parse_g1(env, gamma_beta_1_obj);

    // G2 gamma_beta_2
    jfieldID gamma_beta_2_field =
        env->GetFieldID(cls, "gamma_beta_2", "Lcn/edu/zjucst/jni/G2;");
    jobject gamma_beta_2_obj = env->GetObjectField(jvk, gamma_beta_2_field);
    libff::G2<ppT> gamma_beta_2 = parse_g2(env, gamma_beta_2_obj);

    // G2 z
    jfieldID z_field = env->GetFieldID(cls, "z", "Lcn/edu/zjucst/jni/G2;");
    jobject z_obj = env->GetObjectField(jvk, z_field);
    libff::G2<ppT> z = parse_g2(env, z_obj);

    // G1 ic[]
    jfieldID ic_field = env->GetFieldID(cls, "ic", "[Lcn/edu/zjucst/jni/G1;");
    jobjectArray ic_obj = (jobjectArray)env->GetObjectField(jvk, ic_field);
    std::vector<libff::G1<ppT>> ic;
    for (int i = 0; i < env->GetArrayLength(ic_obj); i++) {
        jobject jic = env->GetObjectArrayElement(ic_obj, i);
        ic.push_back(parse_g1(env, jic));
    }

    accumulation_vector<libff::G1<ppT> > _ic;
    _ic.first = ic[0];
    // Make left elements a vector
    std::vector <libff::G1<ppT>> left_elements;
    for (int i = 1; i < ic.size(); i++) {
        left_elements.push_back(ic[i]);
    }
    _ic.rest = sparse_vector<libff::G1<ppT>>(std::move(left_elements));

    return r1cs_ppzksnark_verification_key<ppT>(a, b, c, gamma, gamma_beta_1,
                                                gamma_beta_2, z, _ic);
}

r1cs_ppzksnark_proof<ppT> parse_proof(JNIEnv *env, jobject jproof) {
    jclass cls = env->GetObjectClass(jproof);

    // G1 a
    jfieldID a_id = env->GetFieldID(cls, "a", "Lcn/edu/zjucst/jni/G1;");
    jobject a_obj = env->GetObjectField(jproof, a_id);
    auto a = parse_g1(env, a_obj);

    // G1 a_p
    jfieldID a_p_id = env->GetFieldID(cls, "a_p", "Lcn/edu/zjucst/jni/G1;");
    jobject a_p_obj = env->GetObjectField(jproof, a_p_id);
    auto a_p = parse_g1(env, a_p_obj);

    // G2 b
    jfieldID b_id = env->GetFieldID(cls, "b", "Lcn/edu/zjucst/jni/G2;");
    jobject b_obj = env->GetObjectField(jproof, b_id);
    auto b = parse_g2(env, b_obj);

    // G1 b_p
    jfieldID b_p_id = env->GetFieldID(cls, "b_p", "Lcn/edu/zjucst/jni/G1;");
    jobject b_p_obj = env->GetObjectField(jproof, b_p_id);
    auto b_p = parse_g1(env, b_p_obj);

    // G1 c
    jfieldID c_id = env->GetFieldID(cls, "c", "Lcn/edu/zjucst/jni/G1;");
    jobject c_obj = env->GetObjectField(jproof, c_id);
    auto c = parse_g1(env, c_obj);

    // G1 c_p
    jfieldID c_p_id = env->GetFieldID(cls, "c_p", "Lcn/edu/zjucst/jni/G1;");
    jobject c_p_obj = env->GetObjectField(jproof, c_p_id);
    auto c_p = parse_g1(env, c_p_obj);

    // G1 h
    jfieldID h_id = env->GetFieldID(cls, "h", "Lcn/edu/zjucst/jni/G1;");
    jobject h_obj = env->GetObjectField(jproof, h_id);
    auto h = parse_g1(env, h_obj);

    // G1 k
    jfieldID k_id = env->GetFieldID(cls, "k", "Lcn/edu/zjucst/jni/G1;");
    jobject k_obj = env->GetObjectField(jproof, k_id);
    auto k = parse_g1(env, k_obj);

    r1cs_ppzksnark_proof<ppT> res;
    res.g_A.g = a;
    res.g_A.h = a_p;
    res.g_B.g = b;
    res.g_B.h = b_p;
    res.g_C.g = c;
    res.g_C.h = c_p;
    res.g_H = h;
    res.g_K = k;
    return res;
}

// Create a long long from a jBigint object.
long long parse_bigint(JNIEnv *env, jobject jbigint) {
    jclass bigint_class = env->FindClass("java/math/BigInteger");
    jmethodID bigint_toString =
        env->GetMethodID(bigint_class, "toString", "()Ljava/lang/String;");
    jstring jstr = (jstring)env->CallObjectMethod(jbigint, bigint_toString);
    const char *cstr = env->GetStringUTFChars(jstr, NULL);

    return std::stoll(cstr);
}
}  // namespace jni_from_java
#endif