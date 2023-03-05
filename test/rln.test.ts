import chai from "chai";
const assert = chai.assert;
import * as path from "path";
const tester = require("circom_tester").wasm;
import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree";
import poseidon from "poseidon-lite";
const ffjavascript = require("ffjavascript");


// ffjavascript has no types so leave circuit with untyped
type CircuitT = any;

const SNARK_FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
const F = new ffjavascript.ZqField(SNARK_FIELD_SIZE);

const circuitPath = path.join(__dirname, "..", "circuits", "rln.circom");

// MERKLE TREE
const MERKLE_TREE_DEPTH = 20;
const MERKLE_TREE_ZERO_VALUE = BigInt(0);

function genFieldElement() {
    return F.random()
}

function genMerkleProof(elements: BigInt[], leafIndex: number) {
    const tree = new IncrementalMerkleTree(poseidon, MERKLE_TREE_DEPTH, MERKLE_TREE_ZERO_VALUE, 2);
    for (let i = 0; i < elements.length; i++) {
        tree.insert(elements[i]);
    }
    const merkleProof = tree.createProof(leafIndex)
    merkleProof.siblings = merkleProof.siblings.map((s) => s[0])
    return merkleProof
}

describe("Check Merkle tree Circuit", function () {
    let circuit: CircuitT;

    this.timeout(10000000);

    before(async function () {
        circuit = await tester(circuitPath);
    });

    it("Should generate witness with correct outputs", async () => {
        // Public inputs
        const x = genFieldElement();
        const externalNullifier = genFieldElement();
        // Private inputs
        const identitySecret = genFieldElement();
        const identitySecretCommitment = poseidon([identitySecret]);
        const merkleProof = genMerkleProof([identitySecretCommitment], 0)
        const merkleRoot = merkleProof.root
        const inputs = {
            // Private inputs
            identitySecret,
            pathElements: merkleProof.siblings,
            identityPathIndex: merkleProof.pathIndices,
            // Public inputs
            x,
            externalNullifier,
        }

        const a1 = poseidon([identitySecret, externalNullifier]);
        // y = identitySecret + a1 * x
        const y = F.normalize(identitySecret + a1 * x);
        const nullifier = poseidon([a1]);

        // Test: should generate proof if inputs are correct
        const witness: bigint[] = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);

        async function getSignal(witness: bigint[], name: string) {
            const prefix = "main"
            // E.g. the full name of the signal "root" is "main.root"
            // You can look up the signal names using `circuit.getDecoratedOutput(witness))`
            const signalFullName = `${prefix}.${name}`
            await circuit.loadSymbols()
            // symbols[n] = { labelIdx: 1, varIdx: 1, componentIdx: 142 },
            const signalMeta = circuit.symbols[signalFullName]
            // Assigned value of the signal is located in the `varIdx`th position
            // of the witness array
            const indexInWitness = signalMeta.varIdx
            return BigInt(witness[indexInWitness]);
        }

        const outputRoot = await getSignal(witness, "root")
        const outputA1 = await getSignal(witness, "a1")
        const outputY = await getSignal(witness, "y")
        const outputNullifier = await getSignal(witness, "nullifier")

        assert.equal(outputA1, a1)
        assert.equal(outputY, y)
        assert.equal(outputNullifier, nullifier)
        assert.equal(outputRoot, merkleRoot)
    });

});