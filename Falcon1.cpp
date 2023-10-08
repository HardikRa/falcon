#include <jni.h>
#include "falcon.hpp"
#include "FalconDemo1.h"

extern "C" JNIEXPORT jobject JNICALL Java_FalconDemo1_keygens(JNIEnv* env, jclass obj) {
    // Create a new Java KeyPair object
    jclass keyPairClass = env->FindClass("java/security/KeyPair");
    jmethodID keyPairConstructor = env->GetMethodID(keyPairClass, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    jobject keyPair = env->NewObject(keyPairClass, keyPairConstructor, nullptr, nullptr);

    // Generate the keypair using the falcon keygen function
    constexpr size_t pklen = falcon_utils::compute_pkey_len<512>();
    constexpr size_t sklen = falcon_utils::compute_skey_len<512>();
    constexpr size_t siglen = falcon_utils::compute_sig_len<512>();

    uint8_t* pkey = static_cast<uint8_t*>(std::malloc(pklen));
    uint8_t* skey = static_cast<uint8_t*>(std::malloc(sklen));
    uint8_t* sig = static_cast<uint8_t*>(std::malloc(siglen));
    falcon::keygen<512>(pkey, skey);

    // Create a new Java PublicKey object from the generated public key
    jclass publicKeyClass = env->FindClass("java/security/PublicKey");
    jmethodID publicKeyConstructor = env->GetMethodID(publicKeyClass, "<init>", "([B)V");
    jbyteArray publicKeyBytes = env->NewByteArray(pklen);
    env->SetByteArrayRegion(publicKeyBytes, 0, pklen, reinterpret_cast<jbyte*>(pkey));
    jobject publicKey = env->NewObject(publicKeyClass, publicKeyConstructor, publicKeyBytes);

    // Create a new Java PrivateKey object from the generated private key
    jclass privateKeyClass = env->FindClass("java/security/PrivateKey");
    jmethodID privateKeyConstructor = env->GetMethodID(privateKeyClass, "<init>", "([B)V");
    jbyteArray privateKeyBytes = env->NewByteArray(sklen);
    env->SetByteArrayRegion(privateKeyBytes, 0, sklen, reinterpret_cast<jbyte*>(skey));
    jobject privateKey = env->NewObject(privateKeyClass, privateKeyConstructor, privateKeyBytes);

    // Set the public and private keys in the KeyPair object
    jmethodID setPublicKeyMethod = env->GetMethodID(keyPairClass, "setPublic", "(Ljava/security/PublicKey;)V");
    env->CallVoidMethod(keyPair, setPublicKeyMethod, publicKey);
    jmethodID setPrivateKeyMethod = env->GetMethodID(keyPairClass, "setPrivate", "(Ljava/security/PrivateKey;)V");
    env->CallVoidMethod(keyPair, setPrivateKeyMethod, privateKey);

    std::free(pkey);
    std::free(skey);
    std::free(sig);

    return keyPair;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_FalconDemo1_sign(JNIEnv *env, jclass obj, jbyteArray jskey, jbyteArray jmsg, jint jmsglen, jbyteArray jsig) {
    // Convert Java byte arrays to C++ uint8_t arrays
    jbyte* skey = env->GetByteArrayElements(jskey, NULL);
    jbyte* msg = env->GetByteArrayElements(jmsg, NULL);
    jbyte* sig = env->GetByteArrayElements(jsig, NULL);

    // Convert Java int to C++ size_t
    size_t msglen = static_cast<size_t>(jmsglen);

    // Sign message using FALCON512 private key
    // const bool _signed = 
    falcon::sign<512>(reinterpret_cast<uint8_t*>(skey), reinterpret_cast<uint8_t*>(msg), msglen, reinterpret_cast<uint8_t*>(sig));

    jbyteArray jresult = env->NewByteArray(666);
    env->SetByteArrayRegion(jresult, 0, msglen, sig);

    // Release Java byte arrays
    env->ReleaseByteArrayElements(jmsg, msg, JNI_ABORT);
    env->ReleaseByteArrayElements(jskey, skey, JNI_ABORT);
    env->ReleaseByteArrayElements(jsig, sig, JNI_ABORT);

    return jresult;
}

extern "C" JNIEXPORT jboolean JNICALL Java_FalconDemo1_verify(JNIEnv *env, jclass obj, jbyteArray jpkey, jbyteArray jmsg, jint jmsglen, jbyteArray jsig) {
    // Convert Java byte arrays to C++ uint8_t arrays
    jbyte* pkey = env->GetByteArrayElements(jpkey, NULL);
    jbyte* msg = env->GetByteArrayElements(jmsg, NULL);
    jbyte* sig = env->GetByteArrayElements(jsig, NULL);

    // Convert Java int to C++ size_t
    size_t msglen = static_cast<size_t>(jmsglen);

    // Verify message signature using FALCON512 public key
    const bool _verified = falcon::verify<512>(reinterpret_cast<uint8_t*>(pkey), reinterpret_cast<uint8_t*>(msg), msglen, reinterpret_cast<uint8_t*>(sig));

    // Release Java byte arrays
    env->ReleaseByteArrayElements(jmsg, msg, JNI_ABORT);
    env->ReleaseByteArrayElements(jpkey, pkey, JNI_ABORT);
    env->ReleaseByteArrayElements(jsig, sig, JNI_ABORT);

    return static_cast<jboolean>(_verified);
}