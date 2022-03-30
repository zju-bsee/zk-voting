#ifndef SHA256_GADGET_HPP
#define SHA256_GADGET_HPP

#include <libff/algebra/fields/field_utils.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

using namespace libsnark;

const size_t sha256_digest_len = 256;

bool sha256_padding[256] = {
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};

template <typename FieldT>
class sha256_gadget : public gadget<FieldT> {
   public:
    // R1CS input
    pb_variable_array<FieldT> input_as_field_elements;
    // Unpacked R1CS input
    pb_variable_array<FieldT> input_as_bits;

    std::shared_ptr<multipacking_gadget<FieldT>> unpack_inputs;
    std::shared_ptr<digest_variable<FieldT>> h_var;
    std::shared_ptr<digest_variable<FieldT>> r_var;

    // 512 bit block that contains r + padding
    std::shared_ptr<block_variable<FieldT>> hash_r_block;
    // hashing gadget for r
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hash_gadget;

    pb_variable<FieldT> zero;

    // SHA256 length padding
    pb_variable_array<FieldT> padding_var;

    sha256_gadget(protoboard<FieldT> &pb)
        : gadget<FieldT>(pb, "sha256_gadget") {
        // 为公共输入分配空间，通过multipacking使用最少的field elements
        const size_t input_size_in_bits = sha256_digest_len;
        {
            const size_t input_size_in_field_elements =
                libff::div_ceil(input_size_in_bits, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_elements,
                                             "input_as_field_elements");
            this->pb.set_input_sizes(input_size_in_field_elements);
        }

        // 分配一个zero变量到面包板
        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

        // SHA256长度padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        // 公共输入h_var为一个digest_variable，长度为256
        h_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h"));
        // 让input_as_bits有
        input_as_bits.insert(input_as_bits.end(), h_var->bits.begin(),
                             h_var->bits.end());

        // 产生并分配一个multipacking_gadget到pb，连接input_as_bits和input_as_field_elements
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(
            this->pb, input_as_bits, input_as_field_elements,
            FieldT::capacity(),
            FMT(this->annotation_prefix, " unpack_inputs")));

        // 分配证明者的输入r_var到pb
        r_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r"));

        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // 为r的哈希初始化一个block gadget
        hash_r_block.reset(new block_variable<FieldT>(
            pb, {r_var->bits, padding_var}, "hash_r_block"));

        // 创建一个sha256_compresssion_function_gadget hash_gadget
        hash_gadget.reset(new sha256_compression_function_gadget<FieldT>(
            pb, IV, hash_r_block->bits, *h_var, "hash_gadget"));
    }

    void generate_r1cs_constraints() {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r_var->generate_r1cs_constraints();

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero,
                                                      FieldT::zero(), "zero");

        // constraint to ensure the hashes validate.
        hash_gadget->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const libff::bit_vector &h,
                               const libff::bit_vector &r) {
        // 将秘密输入填充到r_var中
        r_var->bits.fill_with_bits(this->pb, r);

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        hash_gadget->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h_var->bits.fill_with_bits(this->pb, h);
    }
};

// 用于产生公共输入
template <typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const libff::bit_vector &h) {
    return libff::pack_bit_vector_into_field_element_vector<FieldT>(h);
}

#endif