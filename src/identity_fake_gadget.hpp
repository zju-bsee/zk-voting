#ifndef IDENTITY_FAKE_GADGET
#define IDENTITY_FAKE_GADGET

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "util.hpp"

namespace identity {
template <typename FieldT>
class identity_gadget : public gadget<FieldT> {
   public:
    // Voter num
    std::vector<long long> voters;
    // Private input
    pb_variable<FieldT> x;
    // Intermediate output
    pb_variable_array<FieldT> minus;
    pb_variable_array<FieldT> multiply;

    identity_gadget(protoboard<FieldT> &pb, std::vector<long long> voter_ids)
        : gadget<FieldT>(pb, "sha256_gadget"), voters(voter_ids) {
        size_t num_voters = voters.size();
        if (num_voters <= 1) {
            return;
        }

        // Prover's id
        x.allocate(pb, "prover-id");
        // Minus intermediate variables: N
        minus.resize(num_voters);
        minus.allocate(this->pb, num_voters, "minus-");
        // Multiply intermediate variables: N - 1
        multiply.resize(num_voters - 1);
        multiply.allocate(this->pb, num_voters - 1, "multiply-");

        // generate_r1cs_constraint()
        // Minus
        for (int i = 0; i < num_voters; i++) {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(x - voter_ids[i], 1, minus[i]));
        }
        // Multiply
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(minus[0], minus[1], multiply[0]));
        for (int i = 1; i < num_voters - 1; i++) {
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                multiply[i - 1], minus[i + 1], multiply[i]));
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
        for (int i = 0; i < num_voters; i++) {
            this->pb.val(minus[i]) = id - voters[i];
            minusVals.push_back(id - voters[i]);
        }
        // Multiply
        int prev_multiply = minusVals[0] * minusVals[1];
        this->pb.val(multiply[0]) = prev_multiply;
        for (int i = 1; i < num_voters - 1; i++) {
            prev_multiply = prev_multiply * minusVals[i + 1];
            this->pb.val(multiply[i]) = prev_multiply;
        }
    }
};
}  // namespace identity

#endif