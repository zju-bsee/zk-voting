/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class cn_edu_zjucst_jni_ZKVotingJNI */

#ifndef _Included_cn_edu_zjucst_jni_ZKVotingJNI
#define _Included_cn_edu_zjucst_jni_ZKVotingJNI
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     cn_edu_zjucst_jni_ZKVotingJNI
 * Method:    generateVoterKeys
 * Signature: ([Ljava/lang/String;)Lcn/edu/zjucst/jni/Key;
 */
JNIEXPORT jobject JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_generateVoterKeys
  (JNIEnv *, jclass, jobjectArray);

/*
 * Class:     cn_edu_zjucst_jni_ZKVotingJNI
 * Method:    verifyVoterProof
 * Signature: (Lcn/edu/zjucst/jni/Proof;Lcn/edu/zjucst/jni/VerifyingKey;)Z
 */
JNIEXPORT jboolean JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_verifyVoterProof
  (JNIEnv *, jclass, jobject, jobject);

/*
 * Class:     cn_edu_zjucst_jni_ZKVotingJNI
 * Method:    generateVoterProof
 * Signature: ([BLjava/math/BigInteger;[Ljava/lang/String;)Lcn/edu/zjucst/jni/Proof;
 */
JNIEXPORT jobject JNICALL Java_cn_edu_zjucst_jni_ZKVotingJNI_generateVoterProof
  (JNIEnv *, jclass, jbyteArray, jobject, jobjectArray);

#ifdef __cplusplus
}
#endif
#endif