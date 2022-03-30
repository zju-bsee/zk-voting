#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "sha256_gadget.hpp"

using namespace libsnark;
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

// 生成zk-SNARK密钥对
template <typename ppT>
r1cs_gg_ppzksnark_keypair<ppT> generate_keypair() {
    protoboard<FieldT> pb;

    sha256_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();

    return r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system());
}

// 生成zk-SNARK证明
template <typename ppT>
r1cs_gg_ppzksnark_proof<ppT> generate_proof(
    const r1cs_gg_ppzksnark_proving_key<ppT> &pk, const libff::bit_vector &h1,
    const libff::bit_vector &r1) {
    // 创建一个protoboard
    protoboard<FieldT> pb;

    // 创建一个gadget
    sha256_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(h1, r1);

    // assert(pb.is_satisfied());
    return r1cs_gg_ppzksnark_prover<ppT>(pk, pb.primary_input(),
                                         pb.auxiliary_input());
}

// 验证zk-SNARK证明
template <typename ppT>
bool verify_proof(r1cs_gg_ppzksnark_verification_key<ppT> vk,
                  r1cs_gg_ppzksnark_proof<ppT> proof,
                  const libff::bit_vector &h1) {
    const r1cs_primary_input<FieldT> input = l_input_map<FieldT>(h1);

    return r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, input, proof);
}

// 测试样例
template <typename ppT>
bool run_test(r1cs_gg_ppzksnark_keypair<ppT> &keypair, bool swap) {
    std::vector<bool> h_vector(256);
    std::vector<bool> r_vector(256);
    {
        h_vector = libff::int_list_to_bits(
            {169, 231, 96,  189, 221, 234, 240, 85,  213, 187, 236,
             114, 100, 185, 130, 86,  231, 29,  123, 196, 57,  225,
             159, 216, 34,  190, 123, 97,  14,  57,  180, 120},
            8);
        r_vector = libff::int_list_to_bits(
            {180, 34,  250, 166, 200, 177, 240, 137, 204, 219, 178,
             17,  34,  14,  66,  65,  203, 6,   191, 16,  141, 210,
             73,  136, 65,  136, 152, 60,  117, 24,  101, 18},
            8);
    }

    // swap将两个vector交换，用于测试hash正常工作
    if (swap) {
        std::swap(h_vector, r_vector);
    }

    auto proof = generate_proof<ppT>(keypair.pk, h_vector, r_vector);
    std::cout << "Proof generated!" << std::endl;

    return verify_proof(keypair.vk, proof, h_vector);
}

int main(void) {
    // 初始化曲线参数
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // 产生测试密钥对
    auto keypair = generate_keypair<default_r1cs_gg_ppzksnark_pp>();

    std::cout << run_test(keypair, false) << std::endl;
    // std::cout << run_test(keypair, true) << std::endl;

    return 0;
}