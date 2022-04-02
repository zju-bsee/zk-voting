#ifndef IDENTITY_FAKE_GADGET
#define IDENTITY_FAKE_GADGET

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "util.hpp"

namespace identity {
template <typename FieldT>
class identity_gadget : public gadget<FieldT> {
   public:
    // Private input
    pb_variable<FieldT> x;
    // Every voter has a variable to represent them.
    pb_variable_array<FieldT> voter_ids;
    // Intermediate output
    pb_variable_array<FieldT> minus;
    pb_variable_array<FieldT> multiply;

    identity_gadget(protoboard<FieldT> &pb, unsigned int voter_num)
        : gadget<FieldT>(pb, "sha256_gadget") {
        // Public Voters' id: N
        voter_ids.resize(voter_num);
        voter_ids.allocate(this->pb, voter_num, "voters-");
        // Prover's id: 1
        x.allocate(pb, "prover-id");
        // Minus intermediate variables: N
        minus.resize(voter_num);
        minus.allocate(this->pb, voter_num, "minus-");
        // Multiply intermediate variables: N - 1
        multiply.resize(voter_num - 1);
        multiply.allocate(this->pb, voter_num - 1, "multiply-");
    }

    void generate_r1cs_constraints() {
        int voter_num = voter_ids.size();

        // Minus
        for (int i = 0; i < voter_num; i++) {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(x - voter_ids[i], 1, minus[i]));
        }
        // Multiply
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(minus[0], minus[1], multiply[0]));
        for (int i = 1; i < voter_num - 1; i++) {
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                multiply[i - 1], minus[i + 1], multiply[i]));
        }
        // Output
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(1, multiply[voter_num - 2], 0));

        this->pb.set_input_sizes(voter_num);
    }

    void generate_r1cs_witness(int id, vector<int> &voters) {
        int voter_num = voter_ids.size();
        assert(voter_num == voters.size());
        vector<int> minusVals;

        // Prover
        this->pb.val(x) = id;
        // Voters
        for (int i = 0; i < voters.size(); i++) {
            this->pb.val(voter_ids[i]) = voters[i];
        }
        // Minus
        for (int i = 0; i < voter_num; i++) {
            this->pb.val(minus[i]) = id - voters[i];
            minusVals.push_back(id - voters[i]);
        }
        // Multiply
        int prev_multiply = minusVals[0] * minusVals[1];
        this->pb.val(multiply[0]) = prev_multiply;
        for (int i = 1; i < voter_num - 1; i++) {
            prev_multiply = prev_multiply * minusVals[i + 1];
            this->pb.val(multiply[i]) = prev_multiply;
        }
    }
};
}  // namespace identity

#endif