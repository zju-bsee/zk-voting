package cn.edu.zjucst.jni;

import java.math.BigInteger;

public class ZKVotingJNI {
    private Key key;
    private BigInteger[] voterIDs;

    // 引入lib-zkvoting.so
    static {
        System.loadLibrary("zkvoting");
    }

    // 为了避免重复调用JNI生成命题，验证前需要实例化一个ZKVotingJNI对象
    // TODO: 当前电路voterIDs只能传int范围，电路完善后传sha256的hash值
    public ZKVotingJNI(Key key, BigInteger[] voterIDs) {
        this.key = key;
        this.voterIDs = voterIDs;
    }

    // Note: 相同数量的选民数电路相同，但是多次调用会产生不同的key
    private static native Key generateVoterKeys(int voterNum);

    /**
     * 生成选民的密钥
     * @param voterNum 选民数量
     * @return 验证者、证明者密钥
     */
    public static Key GenerateVoterKeys(int voterNum) {
        if (voterNum <= 1) {
            return null;
        }
        return generateVoterKeys(voterNum);
    }

    private native boolean verifyVoterProof(Proof proof);

    /**
     * 验证选民的证明
     * @param proof 选民的证明
     * @return 验证通过返回true，否则返回false
     */
    public boolean VerifyVoterProof(Proof proof) {
        if (this.voterIDs.length <= 2) {
            return false;
        }
        return verifyVoterProof(proof);
    }

    public static void main(String[] args) {
        // 为选民数3的选举活动产生key
        Key key = GenerateVoterKeys(3);
        System.out.println(key);

        // 测试选举proof验证
        BigInteger[] voterIDs = new BigInteger[3];
        voterIDs[0] = new BigInteger("1");
        voterIDs[1] = new BigInteger("2");
        voterIDs[2] = new BigInteger("3");

        System.out.println(new ZKVotingJNI(key, voterIDs).VerifyVoterProof(null));
    }
}

class Key {
    private ProvingKey provingKey;
    private VerifyingKey verifyingKey;

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
    public G1 alpha;
    public G1 beta_g1;
    public G2 beta_g2;
    public G1 delta_g1;
    public G2 delta_g2;

    public ProvingKey(G1 alpha_g1, G1 beta_g1, G2 beta_g2, G1 delta_g1, G2 delta_g2) {
        this.alpha = alpha_g1;
        this.beta_g1 = beta_g1;
        this.beta_g2 = beta_g2;
        this.delta_g1 = delta_g1;
        this.delta_g2 = delta_g2;
    }

    @Override
    public String toString() {
        return "{" +
                " alpha_g1='" + alpha + "'" +
                ", beta_g1='" + beta_g1 + "'" +
                ", beta_g2='" + beta_g2 + "'" +
                ", delta_g1='" + delta_g1 + "'" +
                ", delta_g2='" + delta_g2 + "'" +
                "}";
    }
}

class VerifyingKey {
    public G1 alpha;
    public G2 beta;
    public G2 gamma;
    public G2 delta;
    public G1[] gamma_abc;

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
    public BigInteger x;
    public BigInteger y;

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
        return "{" +
                " x0='" + x0 + "'" +
                ", x1='" + x1 + "'" +
                ", y0='" + y0 + "'" +
                ", y1='" + y1 + "'" +
                "}";
    }
}