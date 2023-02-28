pragma circom 2.1.0;

include "./incrementalMerkleTree.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template RLN(depth) {
    // Private signals
    signal input identity_secret;
    signal input path_elements[depth];
    signal input identity_path_index[depth];

    // Public signals
    signal input x;
    signal input external_nullifier;

    // Outputs
    signal output y;
    signal output root;
    signal output nullifier;

    // Identity commitment calculation
    signal identity_commitment <== Poseidon(1)([identity_secret]);

    // Merkle tree inclusion proof // Outputs the root
    root <== MerkleTreeInclusionProof(depth)(identity_commitment, identity_path_index, path_elements);

    // Linear equation constraints:
    // a_1 = Poseidon(identity_secret, external_nullifier)
    // y = a_0 + a_1 * x
    // internal_nullifier = Poseidon(a_1)
    signal a_1 <== Poseidon(2)([identity_secret, external_nullifier]);
    y <== identity_secret + a_1 * x;

    nullifier <== Poseidon(1)([a_1]);
}

component main { public [x, external_nullifier] } = RLN(20);
