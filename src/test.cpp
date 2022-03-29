#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "util.hpp"

using namespace libsnark;
using namespace std;

// Default curve for G16.
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

// Prove x^3 + x + 5 == out
template <typename T>
protoboard<FieldT> generate_circuit_pb(int val) {
    // Create a protoboard.
    protoboard<FieldT> pb;

    // Define variables and allocate them to the protoboard.
    // [1, x:0, sym_1:0, y:0, sym_2:0, out:0]
    pb_variable<FieldT> x;
    pb_variable<FieldT> sym_1;
    pb_variable<FieldT> y;
    pb_variable<FieldT> sym_2;
    pb_variable<FieldT> out;
    out.allocate(pb, "out");
    x.allocate(pb, "x");
    sym_1.allocate(pb, "sym_1");
    y.allocate(pb, "y");
    sym_2.allocate(pb, "sym_2");

    // Set public input size.
    // Here the fist allocated variable is the private input.
    pb.set_input_sizes(1);

    // Add R1CS constraints to protoboard
    // x*x = sym_1
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1));
    // sym_1 * x = y
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y));
    // y + x = sym_2
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2));
    // sym_2 + 5 = ~out
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out));

    // Add witness values
    // Variable here is used to locate where to put value to pb's input vector.
    pb.val(out) = 35;
    pb.val(x) = val;
    pb.val(sym_1) = 9;
    pb.val(y) = 27;
    pb.val(sym_2) = 30;

    return pb;
}

int main(int argc, char *argv[]) {
    // Initialize the curve parameters.
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // Get my proving input from the argument
    assert(argc == 2);
    int private_val;
    sscanf(argv[1], "%d", &private_val);

    // Get the protoboard for the circuit.
    const auto pb =
        generate_circuit_pb<default_r1cs_gg_ppzksnark_pp>(private_val);

    // Get the constraint system ant generate key pairs.
    const auto constraint_system = pb.get_constraint_system();
    const auto keypair =
        r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(
            pb.get_constraint_system());

    // Prove
    const auto proof =
        prove(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify
    const bool verified = verify(keypair.vk, pb.primary_input(), proof);

    cout << "Number of R1CS constraints: "
         << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    // Serialize verification key
    serialize_vk(keypair.vk, "vk-data");

    // Serialize proving key
    serialize_proof(proof, "proof-data");

    return 0;
}