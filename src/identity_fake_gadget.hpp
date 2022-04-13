#ifndef IDENTITY_FAKE_GADGET
#define IDENTITY_FAKE_GADGET

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "util.hpp"

// It should be large or it can be easily cracked.
const long long MOD = 1000000009;

namespace identity {
template <typename FieldT>
class identity_gadget : public gadget<FieldT> {
   public:
    // Voter count
    std::vector<long long> voters;
    // Private input
    pb_variable<FieldT> x;
    // Intermediate output
    pb_variable_array<FieldT> minus;
    pb_variable_array<FieldT> multiply;
    pb_variable_array<FieldT> quotient;
    pb_variable_array<FieldT> remainder;

    identity_gadget(protoboard<FieldT> &pb, std::vector<long long> &voter_ids)
        : gadget<FieldT>(pb, "identity_gadget"), voters(voter_ids) {
        size_t num_voters = voters.size();
        if (num_voters <= 1) {
            return;
        }

        // Prover's id
        x.allocate(pb, "prover id");
        // Minus intermediate variables: N
        minus.resize(num_voters);
        std::cout << "Minus size: " << minus.size() << std::endl;
        minus.allocate(this->pb, num_voters, "minus-");
        // Multiply intermediate variables: N - 1
        multiply.resize(num_voters - 1);
        multiply.allocate(this->pb, num_voters, "multiply-");
        // Quotient intermediate variables: N - 1
        quotient.resize(num_voters - 1);
        quotient.allocate(this->pb, num_voters, "quotient-");
        // Remainder intermediate variables: N - 1
        remainder.resize(num_voters - 1);
        remainder.allocate(this->pb, num_voters, "remainder-");

        // Minus
        for (size_t i = 0; i < num_voters; i++) {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(x - voter_ids[i], 1, minus[i]));
        }

        // Multiply: Handle the overflow!!!
        // A * B % MOD = C
        // quotient * MOD = A * B - C
        // multiply = A * B
        // quotient * MOD = multiply - C
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(minus[0], minus[1], multiply[0]));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            quotient[0], MOD, multiply[0] - remainder[0]));
        for (size_t i = 1; i < num_voters - 1; i++) {
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                remainder[i - 1], minus[i + 1], multiply[i]));
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                quotient[i], MOD, multiply[i] - remainder[i]));
        }
        // Output
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(1, multiply[num_voters - 2], 0));
    }

    void generate_r1cs_witness(long long id) {
        size_t num_voters = voters.size();
        std::vector<long long> minusVals;

        // Prover
        this->pb.val(x) = id;

        // Minus
        for (size_t i = 0; i < num_voters; i++) {
            this->pb.val(minus[i]) = id - voters[i];
            minusVals.push_back(id - voters[i]);
        }

        // Multiply
        long long prev_multiply = minusVals[0] * minusVals[1];
        long long prev_remainder = prev_multiply % MOD;
        this->pb.val(multiply[0]) = prev_multiply;
        this->pb.val(quotient[0]) = prev_multiply / MOD;
        this->pb.val(remainder[0]) = prev_remainder;

        for (size_t i = 1; i < num_voters - 1; i++) {
            long long multiply_val = prev_remainder * minusVals[i + 1];

            this->pb.val(multiply[i]) = multiply_val;
            this->pb.val(quotient[i]) = multiply_val / MOD;
            this->pb.val(remainder[i]) = multiply_val % MOD;

            prev_multiply = multiply_val;
            prev_remainder = multiply_val % MOD;
        }
    }
};
}  // namespace identity

#endif