// import * as path from "path";
// import { wasm as wasm_tester } from "circom_tester";
// import {
//     IncrementalMerkleTree,
// } from '@zk-kit/incremental-merkle-tree'
// import poseidon from 'poseidon-lite'
const path = require("path");
const tester = require("circom_tester").wasm;
const incrementalMerkleTree = require("@zk-kit/incremental-merkle-tree");
const poseidon = require("poseidon-lite");

const circuitPath = path.join(__dirname, "..", "circuits", "rln.circom");


// MERKLE TREE
const MERKLE_TREE_DEPTH = 20;
const MERKLE_TREE_ZERO_VALUE = BigInt(0);


// TODO: use bn128 field
function genFieldElement() {
    return BigInt(Math.floor(Math.random() * 1000000));
}

function genMerkleProof(elements, leafIndex) {
    const tree = new incrementalMerkleTree.IncrementalMerkleTree(poseidon, MERKLE_TREE_DEPTH, MERKLE_TREE_ZERO_VALUE, 2);
    for (let i = 0; i < elements.length; i++) {
        tree.insert(elements[i]);
    }
    const merkleProof = tree.createProof(leafIndex)
    merkleProof.siblings = merkleProof.siblings.map((s) => s[0])
    return [merkleProof, merkleProof.root]
}

function calculateA1(identitySecret, externalNullifier) {
    return poseidon([identitySecret, externalNullifier]);
}

function calculateY(identitySecret, a1, x) {
    return identitySecret + a1 * x;
}


describe("Check Merkle tree Circuit", function () {
    let circuit;

    this.timeout(10000000);

    before( async function () {
        circuit = await tester(circuitPath);
    });

    it("Should succeed if ", async () => {
        // Public inputs
        const x = genFieldElement();
        const externalNullifier = genFieldElement();
        // Private inputs
        const identitySecret = genFieldElement();
        const [merkleProof, merkleRoot] = genMerkleProof([x], 0);
        const inputs = {
            // Private inputs
            identitySecret,
            pathElements: merkleProof.siblings,
            identityPathIndex: merkleProof.pathIndices,
            // Public inputs
            x,
            externalNullifier,
        }
        console.log(inputs)

        // y = identitySecret + a1 * x
        const a1 = calculateA1(identitySecret, externalNullifier);
        const y = calculateY(identitySecret, a1, x);
        // console.log(`!@# y =`, y);

        // Test: should generate proof if inputs are correct
        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);

        // n='main.y'
        // witness[varIdx] = k
        async function getSignal(witness, name) {
            const prefix = "main"
            const signalFullName = `${prefix}.${name}`
            await circuit.loadSymbols()
            // symbols[n] = { labelIdx: 1, varIdx: 1, componentIdx: 142 },
            const signalMeta = circuit.symbols[signalFullName]
            const indexInWitness = signalMeta.varIdx
            return BigInt(witness[indexInWitness]);
        }

        // const outputY = await getSignal(witness, "y")
        // console.log(`!@# outputY=`, outputY)
        const outputRoot = await getSignal(witness, "root")
        console.log(`!@# merkleRoot=`, merkleRoot)
        console.log(`!@# outputRoot=`, outputRoot)
        const outputA1 = await getSignal(witness, "a1")
        console.log(`!@# outputA1=`, outputA1)
        console.log(`!@# a1=`, a1)
        const outputY = await getSignal(witness, "y")
        console.log(`!@# outputY=`, outputY)
        console.log(`!@# y=`, y)

        const outputNullifier = await getSignal(witness, "y")
        const nullifier = poseidon([a1]);
        console.log(`!@# outputNullifier=`, outputNullifier)
        console.log(`!@# nullifier=`, nullifier)

        // const outputNullifier = await getSignal(witness, "nullifier")
        // console.log(`!@# outputNullifier=`, outputNullifier)
        // const nullifier = poseidon([identitySecret, externalNullifier, x]);

        // console.log(`!@# symbols=`, circuit.symbols)
        // console.log(`!@# merkleRoot in witness`, witness[circuit.getSignalIdx("main.root")])
        // const root =


        // Verify proof?

        // TODO: Check root is correct
        // TODO: Check y is correct
        // TODO: Check nullifier is correct
        // Verify witness?
    });

});