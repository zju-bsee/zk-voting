package cn.edu.zjucst.jni;

import java.math.BigInteger;

public class ZKVotingJNI {
    // 引入lib-zkvoting.so
    static {
        System.loadLibrary("zkvoting");
    }

    // 根据选举选民数产生身份证明电路对应key
    // private static native int generateIdentityKeys(int voterNum);
    public static native int hello(int i);

    public static int GenerateVoterKeys(int voterNum) {
        // return generateIdentityKeys(voterNum);
        return voterNum;
    }

    public static void main(String[] args) {
        System.out.println(GenerateVoterKeys(100));
    }

    // // 根据候选人数目产生电路对应key
    // public static Key GenerateBallotKeys(int candidateNum) {
    // byte[] keyBytes = generateBallotKeys(candidateNum);
    // return new Key(keyBytes);
    // }

    // // 根据(选民哈希列表，选民哈希)产生选举证明
    // private static Proof GenerateVotingProof(ProvingKey provingKey, byte[][]
    // idHashs, byte[] idHash) {
    // byte[] proofBytes = generateVotingProof(provingKey.serialize(), idHashs,
    // idHash);
    // return new Proof(proofBytes);
    // }

    // // 根据(候选人数，选票)产生选票证明
    // private static Proof GenerateBallotProof(ProvingKey provingKey, int
    // candidateNum, byte[] ballot) {
    // byte[] proofBytes = generateBallotProof(provingKey.serialize(), candidateNum,
    // ballot);
    // return new Proof(proofBytes);
    // }

    // // 根据(验证密钥，选举人证明，选民哈希列表)验证选举人证明
    // private static boolean VerifyVotingProof(VerifyingKey verifyingKey, Proof
    // proof, byte[][] idHashs) {
    // byte[] verifyingKeyBytes = verifyingKey.serialize();
    // byte[] proofBytes = proof.serialize();
    // return verifyVotingProof(verifyingKeyBytes, proofBytes, idHashs);
    // }

    // // 根据（验证密钥，选票证明，）
    // private static boolean VerifyBallotProof(VerifyingKey verifyingKey, Proof
    // proof) {
    // byte[] verifyingKeyBytes = verifyingKey.serialize();
    // byte[] proofBytes = proof.serialize();
    // return verifyBallotProof(verifyingKeyBytes, proofBytes);
    // }

    // private static native byte[] generateBallotKeys(int candidateNum);

    // private static native byte[] generateVotingProof(byte[] provingKey, byte[][]
    // idHashs, byte[] idHash);

    // private static native byte[] generateBallotProof(byte[] provingKey, int
    // candidateNum, byte[] ballot);

    // private static native boolean verifyVotingProof(byte[] verifyingKey, byte[]
    // proof, byte[][] idHashs);

    // private static native boolean verifyBallotProof(byte[] verifyingkey, byte[]
    // proof);
}

class Key {
    private final ProvingKey provingKey;
    private final VerifyingKey verifyingKey;

    public Key(ProvingKey provingKey, VerifyingKey verifyingKey) {
        this.provingKey = provingKey;
        this.verifyingKey = verifyingKey;
    }

    @Override
    public String toString() {
        return "{" +
                " provingKey='" + provingKey + "'" +
                ", verifyingKey='" + verifyingKey + "'" +
                "}";
    }
}

class ProvingKey {
    // TODO: 动态字段还未完整
    public final G1 alpha_g1;
    public final G1 beta_g1;
    public final G2 beta_g2;
    public final G1 delta_g1;
    public final G2 delta_g2;

    public ProvingKey(G1 alpha_g1, G1 beta_g1, G2 beta_g2, G1 delta_g1, G2 delta_g2) {
        this.alpha_g1 = alpha_g1;
        this.beta_g1 = beta_g1;
        this.beta_g2 = beta_g2;
        this.delta_g1 = delta_g1;
        this.delta_g2 = delta_g2;
    }

    @Override
    public String toString() {
        return "{" +
                " alpha_g1='" + alpha_g1 + "'" +
                ", beta_g1='" + beta_g1 + "'" +
                ", beta_g2='" + beta_g2 + "'" +
                ", delta_g1='" + delta_g1 + "'" +
                ", delta_g2='" + delta_g2 + "'" +
                "}";
    }
}

class VerifyingKey {
    public final G1 alpha;
    public final G2 beta;
    public final G2 gamma;
    public final G2 delta;
    public final G1[] gamma_abc;

    public VerifyingKey(G1 alpha, G2 beta, G2 gamma, G2 delta, G1[] gamma_abc) {
        this.alpha = alpha;
        this.beta = beta;
        this.gamma = gamma;
        this.delta = delta;
        this.gamma_abc = gamma_abc;
    }

    @Override
    public String toString() {
        return "{" +
                " alpha='" + alpha + "'" +
                ", beta='" + beta + "'" +
                ", gamma='" + gamma + "'" +
                ", delta='" + delta + "'" +
                ", gamma_abc='" + gamma_abc + "'" +
                "}";
    }
}

class Proof {
    public G1 a;
    public G2 b;
    public G1 c;

    public Proof(G1 a, G2 b, G1 c) {
        this.a = a;
        this.b = b;
        this.c = c;
    }
}

class G1 {
    public final BigInteger x;
    public final BigInteger y;

    public G1(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    @Override
    public String toString() {
        return "{" +
                " x='" + x + "'" +
                ", y='" + y + "'" +
                "}";
    }
}

class G2 {
    public final BigInteger x0;
    public final BigInteger x1;
    public final BigInteger y0;
    public final BigInteger y1;

    public G2(BigInteger x0, BigInteger x1, BigInteger y0, BigInteger y1) {
        this.x0 = x0;
        this.x1 = x1;
        this.y0 = y0;
        this.y1 = y1;
    }

    @Override
    public String toString() {
        return "{" +
                " x0='" + x0 + "'" +
                ", x1='" + x1 + "'" +
                ", y0='" + y0 + "'" +
                ", y1='" + y1 + "'" +
                "}";
    }
}