public class ZKVotingJNI {
    // 引入lib-zkvoting.so
    static {
        System.loadLibrary("zkvoting");
    }

    // 根据选举选民数产生电路对应key
    public static Key GenerateVoterKeys(int voterNum) {
        byte[] keyBytes = generateVoterKeys(voterNum);
        return new Key(keyBytes);
    }

    // 根据候选人数目产生电路对应key
    public static Key GenerateBallotKeys(int candidateNum) {
        byte[] keyBytes = generateBallotKeys(candidateNum);
        return new Key(keyBytes);
    }

    // 根据(选民哈希列表，选民哈希)产生选举证明
    private static Proof GenerateVotingProof(ProvingKey provingKey, byte[][] idHashs, byte[] idHash) {
        byte[] proofBytes = generateVotingProof(provingKey.serialize(), idHashs, idHash);
        return new Proof(proofBytes);
    }

    // 根据(候选人数，选票)产生选票证明
    private static Proof GenerateBallotProof(ProvingKey provingKey, int candidateNum, byte[] ballot) {
        byte[] proofBytes = generateBallotProof(provingKey.serialize(), candidateNum, ballot);
        return new Proof(proofBytes);
    }

    // 根据(验证密钥，选举人证明，选民哈希列表)验证选举人证明
    private static boolean VerifyVotingProof(VerifyingKey verifyingKey, Proof proof, byte[][] idHashs) {
        byte[] verifyingKeyBytes = verifyingKey.serialize();
        byte[] proofBytes = proof.serialize();
        return verifyVotingProof(verifyingKeyBytes, proofBytes, idHashs);
    }

    // 根据（验证密钥，选票证明，）
    private static boolean VerifyBallotProof(VerifyingKey verifyingKey, Proof proof) {
        byte[] verifyingKeyBytes = verifyingKey.serialize();
        byte[] proofBytes = proof.serialize();
        return verifyBallotProof(verifyingKeyBytes, proofBytes);
    }

    private static native byte[] generateVoterKeys(int voterNum);

    private static native byte[] generateBallotKeys(int candidateNum);

    private static native byte[] generateVotingProof(byte[] provingKey, byte[][] idHashs, byte[] idHash);

    private static native byte[] generateBallotProof(byte[] provingKey, int candidateNum, byte[] ballot);

    private static native boolean verifyVotingProof(byte[] verifyingKey, byte[] proof, byte[][] idHashs);

    private static native boolean verifyBallotProof(byte[] verifyingkey, byte[] proof);
}

class Key {
    private ProvingKey provingKey;
    private VerifyingKey verifyingKey;

    public Key(ProvingKey provingKey, VerifyingKey verifyingKey) {
        this.provingKey = provingKey;
        this.verifyingKey = verifyingKey;
    }

    public Key(byte[] bytes) {

    }
}

class ProvingKey {
    public ProvingKey(byte[] bytes) {

    }

    public byte[] serialize() {
        // TODO
        return null;
    }
}

class VerifyingKey {
    public VerifyingKey(byte[] bytes) {

    }

    public byte[] serialize() {
        // TODO
        return null;
    }
}

class Proof {
    public Proof(byte[] bytes) {

    }

    public byte[] serialize() {
        // TODO
        return null;
    }
}
