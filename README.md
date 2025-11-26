███████╗███████╗███╗   ██╗ ██████╗ 

╚══███╔╝██╔════╝████╗  ██║██╔═══██║

  ███╔╝ █████╗  ██╔██╗ ██║██║   ██║

 ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║

███████╗███████╗██║ ╚████║╚██████╔╝

╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ 

Zeno – Zero-Knowledge Privacy Layer on a Solana-Class L1
========================================================

Zeno is a **privacy-preserving Layer-1 blockchain** built as a fork of Solana, with an embedded **zk-SNARK shielded pool** for private transactions.

At its core:

- **Execution & Consensus:** Solana-style PoH + PoS, Sealevel parallel VM  
- **Privacy:** Groth16 zk-SNARKs over BN254, using Poseidon-like hash trees  
- **Model:** Dual-pool system – transparent accounts + shielded notes  
- **Goal:** Zcash-style privacy semantics on a Solana-grade performance base

Zeno allows users and applications to move assets between a transparent layer and a shielded pool, enabling unlinkable deposits, private transfers, and redemptions back to the public domain.

> ⚠️ Zeno is under active development. APIs, circuit parameters, and program layouts are subject to change.

---

## 1. Security Model

Zeno’s shielded layer is designed around a few core invariants:

- No double spends of shielded notes  
- Correct Merkle membership for all spent notes  
- Conservation of value across join/split operations  
- Bounded, well-typed amounts (no overflow or negative values)  
- Binding between proofs and on-chain context (no replay / context swap)

### 1.1 Zero-Knowledge Guarantees

Transactions in the shielded pool rely on **Groth16 zk-SNARKs** (BN254 curve). A proof attests, without revealing underlying secrets, that:

- The prover owns the input notes being spent  
- Those notes exist in the global commitment tree  
- The values of input and output notes satisfy a conservation equation  
- All nullifiers correspond to valid secret inputs and are correctly derived  
- Any “public” amount that leaves/enters the pool matches what is committed in the proof

What is **hidden**:

- Individual note balances  
- Note ownership (public keys / addresses)  
- The link between input and output notes (transaction graph privacy)  

What is **public**:

- A small set of public inputs (Merkle root, nullifiers, commitments, public in/out amounts)  
- Any transparent-layer transfers (e.g., final payout address)

---

## 2. Cryptographic Primitives

Zeno’s privacy layer uses:

- **SNARK-friendly hash (Poseidon-style):**  
  Used to build Merkle trees and derive commitments/nullifiers in a circuit-compatible way.

- **BN254 field arithmetic:**  
  For Groth16 proof verification inside the VM.

- **Incremental Sparse Merkle Tree:**  
  Fixed-depth tree with large capacity (on the order of tens of millions of notes), supporting efficient append and membership proof verification.

- **Optional ciphertext storage:**  
  Encrypted note blobs can be stored on-chain (or off-chain with commitment linkage) for wallet recovery and scanning.

---

## 3. On-Chain Security Invariants

The Zeno shielded pool enforces several invariants at the program level.

### 3.1 Double-Spend Resistance

Every shielded spend emits at least one **nullifier**, which is stored on-chain in a dedicated account:

- **Nullifier PDA:** `["zno-null", nullifier_bytes]`  
- Once a nullifier is created, it **must never be reused**.  
- Any attempt to reuse a nullifier triggers a hard failure (e.g., `ErrorCode::NullifierAlreadyUsed`).

This ensures that each note can only be spent once.

---

### 3.2 Pool Accounting

The shielded pool accounts maintain conservative balance invariants:

- Total value tracked satisfies:

  ```text
  total_deposited >= total_withdrawn
  ```

- The pool PDA must contain enough lamports/tokens to satisfy a payout:

  ```rust
  require!(pool_account.lamports() >= payout, ErrorCode::InsufficientPoolFunds);
  ```

These checks are applied on every withdrawal or pool-modifying operation.

---

### 3.3 Merkle Root Validity

To validate that a note exists in the tree:

- A **Merkle root history buffer** of recent roots is maintained (e.g., last N roots).  
- A proof is considered valid if its root matches **one of the stored roots**.  
- This allows users to generate proofs within a flexible time window without locking them to a single “current” root.

This mitigates issues like:

- Using stale roots outside a defined validity window  
- Exploiting reorgs or outdated proofs to attack the pool

---

### 3.4 Amount Conservation

Inside the circuit, a **join-split equation** is enforced:

```text
(Σ input_note_values) + external_in = (Σ output_note_values) + public_out
```

- `external_in` – net value flowing from transparent layer into shielded pool  
- `public_out` – net value flowing from shielded pool back to transparent layer  

This ensures that the pool cannot be drained or inflated via malformed proofs.

---

### 3.5 Range & Type Checks

All amounts are treated as **unsigned 64-bit integers**:

- Range checks within the circuits ensure all balances and amounts fit into 64 bits.
- On-chain checks prevent integer overflow/underflow when updating balances.

This prevents malformed proofs from introducing invalid numeric states.

---

### 3.6 Nullifier Binding

Nullifiers are derived from secrets bound to the note and spend:

```text
nullifier = Poseidon(view_key, spend_nonce, note_secret, ...)
```

- Without the appropriate secret data, a nullifier cannot be forged in a way that passes circuit verification.
- This ties each nullifier to a specific note and owner, without exposing the owner publicly.

---

## 4. Threat Model & Mitigations (High-Level)

| Attack Type                    | Defense Mechanism                                                                 |
|--------------------------------|-----------------------------------------------------------------------------------|
| Double-spend of notes          | Nullifier accounts; each nullifier is single-use and permanently recorded         |
| Forged Merkle proofs           | zk-SNARK circuits check Merkle paths; on-chain Merkle root history is validated  |
| Pool drain / hidden inflation  | Join-split equation; strict pool accounting invariants                           |
| Amount overflow / underflow    | Circuit-level range checks + on-chain checked arithmetic                         |
| Replay attacks                 | Nonces + PDAs bound to transaction context                                       |
| Proof context malleability     | Public inputs include Merkle root, amounts, and context-specific data            |
| MEV / front-running            | Two-phase withdrawals and PDA commitments to recipient & fee parameters          |
| Unauthorized relayers (if used)| Whitelisting and/or signature checks for relayer authority                       |

---

## 5. Architecture Overview

Zeno’s privacy stack has three main layers:

1. **Circuits + SNARK tooling** – circuits, proving and verification keys  
2. **On-chain programs** – shielded pool logic and proof verification  
3. **Off-chain services (optional)** – relayers, wallets, and prover services

### 5.1 Circuit Generation

Zeno uses `circom` + `snarkjs` (and optionally an internal helper repo) to generate:

- R1CS circuits  
- Proving keys (`*.zkey`)  
- Verification keys (`*.json`)  
- WASM for witness generation

Example pipeline (names are illustrative):

```bash
# Inside circuits/ or a dedicated circuit repo
circom zeno_shield.circom --r1cs --wasm --sym -o build

# Powers of Tau
npx snarkjs powersoftau new bn128 17 build/pot_0000.ptau
npx snarkjs powersoftau contribute build/pot_0000.ptau build/pot_0001.ptau

# Phase 2 setup
npx snarkjs powersoftau prepare phase2 build/pot_0001.ptau build/pot_final.ptau

# Groth16 setup
npx snarkjs groth16 setup build/zeno_shield.r1cs build/pot_final.ptau build/zeno_shield_0000.zkey

# Finalize, contribute, and export verifier key
npx snarkjs zkey contribute build/zeno_shield_0000.zkey build/zeno_shield_final.zkey
npx snarkjs zkey export verificationkey build/zeno_shield_final.zkey build/zeno_shield_vk.json
```

The verification key is then embedded into an on-chain program (e.g., converted into a Rust module or deserialized at runtime).

---

### 5.2 Program Layout (Example)

```text
programs/zeno_shield/src/
├── lib.rs              # Program entrypoint
├── verifier.rs         # Groth16 verifier over BN254
├── instructions/       # Instruction handlers
│   ├── init.rs         # Initialize global shielded state
│   ├── deposit.rs      # Transparent → shielded
│   ├── shielded_tx.rs  # Shielded → shielded join/split
│   ├── withdraw.rs     # Shielded → transparent (two-phase)
│   ├── query.rs        # Optional view/query helpers
│   └── admin.rs        # Migration, emergency ops, etc.
└── state/
    ├── global.rs       # Global pool state (roots, indices, totals)
    ├── note.rs         # Note records (optional, for recovery)
    ├── merkle.rs       # Merkle tree helpers
    ├── nullifier.rs    # Nullifier flags
    ├── prepared_tx.rs  # Two-phase withdrawal state
    ├── constants.rs    # Tree depth, history length, etc.
    ├── errors.rs       # Program-specific errors
    └── utils.rs        # Common helpers
```

---

### 5.3 State Accounts (Conceptual)

> **Note:** Exact structs may differ in the implementation. This is a reference design.

#### Global Shielded State

```rust
pub struct ShieldedGlobalState {
    pub admin: Pubkey,
    pub bump: u8,

    pub pool_bump: u8,
    pub escrow_bump: u8,

    pub next_index: u32,        // Next Merkle leaf index
    pub current_root: [u8; 32], // Latest Merkle root

    pub root_history_idx: u16,  // Circular buffer index
    pub root_history: Vec<[u8; 32]>,

    pub total_deposited: u64,
    pub total_withdrawn: u64,
}
```

**PDAs (example):**

- Global state: `["zno-state"]`  
- Pool vault: `["zno-pool"]`  
- Escrow vault (for rent): `["zno-escrow"]`

---

#### Note Record (Optional On-Chain Storage)

```rust
pub struct ShieldedNote {
    pub bump: u8,
    pub index: u32,             // Merkle index
    pub commitment: [u8; 32],   // Hash of (value, secrets)
    pub owner_hint: Pubkey,     // Only used for recovery / emergency
    pub value: u64,             // Optional plaintext for deposits
    pub ciphertext: Vec<u8>,    // Encrypted note blob (optional)
}
```

**PDA:** `["zno-note", commitment_bytes]`

---

#### Nullifier Flag

```rust
pub struct NullifierFlag {
    pub bump: u8,
}
```

**PDA:** `["zno-null", nullifier_bytes]`

Creating this account marks the corresponding note as spent.

---

#### Prepared Withdrawal (Two-Phase Pattern)

Two-phase withdrawals can help:

- Separate proof verification from actual fund transfer  
- Provide replay protection  
- Lock in recipient and fee terms before execution

```rust
pub struct PreparedWithdrawal {
    pub bump: u8,
    pub executed: bool,

    pub nonce: u64,          // Unique identifier
    pub recipient: Pubkey,   // Final transparent recipient
    pub relayer: Pubkey,     // Optional relayer
    pub to_recipient: u64,   // Amount to user
    pub to_relayer: u64,     // Amount to relayer/fees
}
```

**PDA:** `["zno-prep", nonce_be_bytes]`

---

## 6. Transaction Flows

### 6.1 Deposit (Transparent → Shielded)

1. User calls `deposit` with:
   - Amount  
   - Commitment (for new note)  
   - Optional ciphertext  
2. Program:
   - Transfers lamports/tokens from user into pool PDA  
   - Inserts commitment into Merkle tree  
   - Updates `next_index`, `current_root`, and root history  
   - Optionally records a `ShieldedNote` account  

---

### 6.2 Shielded Transaction (Shielded → Shielded)

1. User generates a proof off-chain showing:
   - Ownership of input notes  
   - Correct Merkle inclusion  
   - Valid join-split equation  
   - Correctly formed new commitments & nullifiers  
2. Transaction submits:
   - zk-SNARK proof  
   - Public inputs (Merkle root, nullifiers, commitments, public amounts, etc.)  
3. Program:
   - Verifies proof via Groth16 verifier  
   - Checks root in history  
   - Creates nullifier PDAs (mark notes spent)  
   - Inserts new output commitments into tree  

This flow never touches transparent balances.

---

### 6.3 Withdrawal (Shielded → Transparent)

A typical two-phase pattern:

**Phase 1 – Prepare**

- Off-chain:
  - User generates shielded proof  
- On-chain:
  - Program verifies proof and pool invariants  
  - Marks nullifiers as used  
  - Inserts any change commitments  
  - Creates a `PreparedWithdrawal` PDA with locked recipient + fee splits

**Phase 2 – Execute**

- Relayer or user calls `execute_withdrawal`:
  - Loads `PreparedWithdrawal`  
  - Checks `executed == false`  
  - Transfers lamports/tokens from pool PDA to:
    - `recipient` (user)  
    - `relayer` (if applicable)  
  - Marks `executed = true`  
  - Updates accounting (`total_withdrawn`) and validates pool invariants again  

---

## 7. Development & Testing

### 7.1 Building the Zeno Node & Tooling

Prerequisites (Ubuntu-like environment):

```bash
sudo apt update
sudo apt install -y \
  git curl build-essential pkg-config libssl-dev libclang-dev cmake python3
```

Install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

Clone and build:

```bash
git clone https://github.com/<org-or-user>/zeno.git
cd zeno

cargo build --release
```

Binaries will include (names may vary depending on the fork stage):

- `zeno-test-validator`  
- `zeno-validator`  
- `zeno-keygen`  
- `zeno` CLI  

---

### 7.2 Running a Local Zeno Validator

```bash
mkdir -p /root/zeno-validator/ledger
zeno-keygen new --outfile ~/validator-keypair.json

zeno-test-validator \
  --ledger /root/zeno-validator/ledger \
  --reset \
  --identity ~/validator-keypair.json \
  --mint $(zeno-keygen pubkey ~/validator-keypair.json) \
  --rpc-port 8899 \
  --limit-ledger-size
```

Set CLI endpoint:

```bash
zeno config set --url http://127.0.0.1:8899
zeno airdrop 10
zeno balance
```

---

## 8. Network Information

> These values are examples; update with actual endpoints when networks are live.

- **Local Devnet RPC:** `http://127.0.0.1:8899`  
- **Public Testnet RPC:** `https://testnet.zenoprivacy.com`  
- **Faucet API:** `https://api.zenoprivacy.com/api/faucet`  

Example faucet request:

```bash
curl -X POST https://api.zenoprivacy.com/api/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "YOUR_PUBLIC_KEY_HERE"}'
```

---

## 9. Explorer & Off-Chain Services

### Explorer

A reference explorer (e.g., Next.js/React) can:

- Display latest blocks, slots, and transactions  
- Query shielded-related on-chain events (roots, pool balances, etc.)  
- Proxy RPC requests server-side to avoid browser CORS issues  

Environment example:

```env
ZENO_RPC_ENDPOINT=https://testnet.zenoprivacy.com
NEXT_PUBLIC_USE_MOCK_DATA=false
```

---

### Relayer (Optional)

A relayer service can:

- Accept withdrawal requests over HTTP/WebSocket  
- Validate memo / payload structure  
- Submit `prepare_withdraw` and `execute_withdraw` on behalf of users  
- Optionally subsidize gas and take a fee

Exact protocol and fee mechanics for Zeno are under design and may evolve.

---

## 10. System Constraints (Conceptual Defaults)

> Concrete values may differ by deployment. These are typical design targets.

- **Tree depth:** e.g. `TREE_DEPTH = 26` → capacity ≈ 67M leaves  
- **Root history length:** e.g. `ROOT_HISTORY = 1000` recent roots  
- **Max input notes per proof:** e.g. `MAX_INPUT_NOTES = 6`  
- **Max output notes per proof:** e.g. `MAX_OUTPUT_NOTES = 6`  
- **Amount type:** `u64` for all balances and amounts  

These parameters trade off:

- Proof size and verification cost  
- Flexibility of join/split patterns  
- Long-term capacity and on-chain storage constraints  

---

## 11. Dependencies (High-Level)

### Rust / On-Chain

- `solana-program` / `zeno-program` (fork)  
- Pairing-friendly elliptic curve library for BN254 verification  
- Poseidon-like hash implementation  
- Usual Rust ecosystem crates (serialization, error handling, etc.)

### ZK Tooling

- `circom` – circuit compiler  
- `snarkjs` – Groth16 keys and proof generation  
- `circomlib` or equivalent – reusable gadgets (hash, Merkle, range checks)

### Off-Chain / JS

- `@solana/web3.js` or equivalent Zeno client  
- Node.js for scripts and relayer services  
- Optional: WebSocket libraries for interactive relayer communication  

---

## 12. Roadmap (High-Level)

- **Phase 1 – Base Chain**
  - Stabilize Solana fork (consensus + runtime)  
  - Launch devnet/testnet RPC endpoints  
  - Basic explorer & faucet

- **Phase 2 – Privacy Layer**
  - Finalize circuits  
  - Implement on-chain Groth16 verifier  
  - End-to-end shielded deposit/transfer/withdraw  
  - Wallet reference implementation

- **Phase 3 – Ecosystem**
  - Integration with wallets and tooling  
  - SDKs for shielded flows (TypeScript/Rust)  
  - Documentation and examples

- **Phase 4 – Security & Mainnet Readiness**
  - External audits (protocol & implementation)  
  - Trusted setup ceremony docs or MPC  
  - Mainnet parameters & validator incentives  

---

## 13. Contributing

Contributions are welcome across:

- Core protocol  
- zk-SNARK circuit design / audits  
- Runtime performance & gas cost optimizations  
- Wallets, explorers, relayers  
- Documentation and tooling

Basic contribution flow:

```bash
git clone https://github.com/<org-or-user>/zeno.git
cd zeno
git checkout -b feature/my-change

# make changes...

git commit -am "Describe your change"
git push origin feature/my-change
```

Then open a pull request against the main repository.

---

## 14. License & Disclaimer

Zeno is open source. See the `LICENSE` file for the full license text.

**Disclaimer:**  
Zeno’s shielded pool and associated cryptography are experimental. Do not commit funds you cannot afford to lose. There may be implementation bugs, cryptographic weaknesses, or operational failures that could lead to loss of funds or privacy.

Before any production use:

- Independent security audits SHOULD be performed  
- Circuits SHOULD be reviewed by experienced cryptographers  
- Operators SHOULD seek legal and regulatory guidance  

Use at your own risk.

