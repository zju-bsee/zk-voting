package cn.edu.zjucst.jni;

import java.math.BigInteger;
import java.util.Arrays;

public class ZKVotingJNI {
    private Key key;
    private BigInteger[] voterIDs;

    // 引入lib-zkvoting.so
    static {
        System.loadLibrary("zkvoting");
    }

    private static native Key generateVoterKeys(String[] voterIDs);

    /**
     * 根据活动选民列表生成选民的密钥
     * 
     * @param voterIDs 选民hash(id)列表
     * @return 验证者、证明者密钥
     */
    public static Key GenerateVoterKeys(BigInteger[] voterIDs) {
        if (voterIDs.length <= 1) {
            return null;
        }

        String[] idStrings = new String[voterIDs.length];
        for (int i = 0; i < voterIDs.length; i++) {
            idStrings[i] = voterIDs[i].toString();
        }

        Key key = generateVoterKeys(idStrings);
        // TODO: 链外存储Pk和Vk文件 + 链上存储SHA256

        return key;
    }

    private static native boolean verifyVoterProof(Proof proof, VerifyingKey vk);

    /**
     * 验证选民的证明
     * 
     * @param 选民的ID，verifyingKey序列化对象
     * @return 验证通过返回true，否则返回false
     */
    public static boolean VerifyVoterProof(Proof proof, VerifyingKey vk) {
        return verifyVoterProof(proof, vk);
    }

    private static native Proof generateVoterProof(byte[] pk, BigInteger secret, String[] voterIDs);

    /**
     * 生成选民身份证明
     * 
     * @param pk     证明者密钥provingKey bytes
     * @param secret=id+salt 证明者秘密输入
     * @return 选民身份证明，若为空证明生成失败
     */
    public static Proof GenerateVoteProof(byte[] pk, BigInteger id, BigInteger salt, BigInteger[] voterIDs) {
        // NOTE: 当前salt+id应为链上id
        // TODO: 实现SHA256证明
        BigInteger bound = new BigInteger("2").pow(63);
        BigInteger secret = id.add(salt);
        secret = secret.mod(bound);

        // Voter String
        String[] voterStrings = new String[voterIDs.length];
        for (int i = 0; i < voterIDs.length; i++) {
            voterStrings[i] = voterIDs[i].toString();
        }

        return generateVoterProof(pk, secret, voterStrings);
    }

    public static void main(String[] args) {
        BigInteger[] voterIDs = new BigInteger[3];
        voterIDs[0] = new BigInteger("1");
        voterIDs[1] = new BigInteger("4");
        voterIDs[2] = new BigInteger("3");

        // 产生Key
        System.out.println("============================================");
        Key key = GenerateVoterKeys(voterIDs);
        System.out.println(key);

        // 测试Prove
        System.out.println("============================================");
        Proof proof = GenerateVoteProof(key.provingKeyBytes, new BigInteger("1"), new BigInteger("1"), voterIDs);
        System.out.println(proof);

        // 测试Verify
        System.out.println(VerifyVoterProof(proof, key.verifyingKey));
    }
}

class Key {
    // 用于证明者使用的pk，链上存储其hash
    public byte[] provingKeyBytes;
    // 用于验证者本地使用的vk，链上存储其hash
    public byte[] verifyingKeyBytes;
    // 用于智能合约和验证者在线使用的vk，链上直接存储用于智能合约验证
    public VerifyingKey verifyingKey;

    @Override
    public String toString() {
        return "VK:\n" + verifyingKey + "\nPK Bytes len: " + provingKeyBytes.length + "\nVK Bytes len: "
                + verifyingKeyBytes.length;
    }
}

class VerifyingKey {
    public G2 a;
    public G1 b;
    public G2 c;
    public G2 gamma;
    public G1 gamma_beta_1;
    public G2 gamma_beta_2;
    public G2 z;
    public G1[] ic;

    public VerifyingKey(G2 a, G1 b, G2 c, G2 gamma, G1 gamma_beta_1, G2 gamma_beta_2, G2 z, G1[] ic) {
        this.a = a;
        this.b = b;
        this.c = c;
        this.gamma = gamma;
        this.gamma_beta_1 = gamma_beta_1;
        this.gamma_beta_2 = gamma_beta_2;
        this.z = z;
        this.ic = ic;
    }

    @Override
    public String toString() {
        return "A:\n" + a + "\nB:\n" + b + "\nC:\n" + c + "\nGamma:\n" + gamma + "\nGamma_beta_1:\n" + gamma_beta_1
                + "\nGamma_beta_2:\n" + gamma_beta_2 + "\nZ:\n" + z + "\nIC:\n" + Arrays.toString(ic);
    }
}

class Proof {
    public G1 a;
    public G1 a_p;
    public G2 b;
    public G1 b_p;
    public G1 c;
    public G1 c_p;
    public G1 h;
    public G1 k;

    public Proof(G1 a, G1 a_p, G2 b, G1 b_p, G1 c, G1 c_p, G1 h, G1 k) {
        this.a = a;
        this.a_p = a_p;
        this.b = b;
        this.b_p = b_p;
        this.c = c;
        this.c_p = c_p;
        this.h = h;
        this.k = k;
    }

    @Override
    public String toString() {
        return "A:\n" + a + "\nA_p:\n" + a_p + "\nB:\n" + b + "\nB_p:\n" + b_p + "\nC:\n" + c + "\nC_p:\n" + c_p
                + "\nH:\n" + h + "\nK:\n" + k;
    }
}

class G1 {
    public BigInteger x;
    public BigInteger y;

    public G1(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    @Override
    public String toString() {
        return "[\"" + x + "\",\"" + y + "\"]";
    }
}

class G2 {
    public BigInteger x0;
    public BigInteger x1;
    public BigInteger y0;
    public BigInteger y1;

    public G2(BigInteger x0, BigInteger x1, BigInteger y0, BigInteger y1) {
        this.x0 = x0;
        this.x1 = x1;
        this.y0 = y0;
        this.y1 = y1;
    }

    @Override
    public String toString() {
        return "[[\"" + x0 + "\",\"" + x1 + "\"],[\"" + y0 + "\",\"" + y1 + "\"]]";
    }
}