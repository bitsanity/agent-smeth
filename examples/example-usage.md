# Agent Smeth — Example Usage

These examples show typical inputs you can pass to the skill (via the `skill.yaml` inputs) and the kind of output you should expect.

> Notes:
> - This skill **may** use a human to sign transactions and broadcast with consent
> - Never provide private keys or seed phrases.

---

## Example 1 — Explain a transaction (with RPC)

**Input**
- intent: "Explain what this transaction did and summarize the receipt."
- chain: "ethereum-mainnet"
- rpc_url: "https://YOUR-RPC-URL"
- tx_hash: "0xYOUR_TRANSACTION_HASH"

**Expected Output**
- A summary of the transaction:
  - from / to
  - value (ETH)
  - gas used / effective gas price (if receipt available)
  - status (success/failure)
  - logs count
- Any detected contract creation (to == null)
- Clear next steps if RPC call fails (rate limits, invalid hash, etc.)

---

## Example 2 — Decode calldata (with ABI)

**Input**
- intent: "Decode this calldata using the ABI."
- chain: "sepolia"
- data: "0xA9059CBB000000000000000000000000...<snip>"
- abi: |
  [
    {
      "type": "function",
      "name": "transfer",
      "stateMutability": "nonpayable",
      "inputs": [
        {"name": "to", "type": "address"},
        {"name": "amount", "type": "uint256"}
      ],
      "outputs": [{"name": "", "type": "bool"}]
    }
  ]

**Expected Output**
- Identified function selector (first 4 bytes)
- Function name: `transfer`
- Decoded params:
  - to: 0x...
  - amount: 12345 (and optionally in token units if decimals are provided separately)
- If ABI decoding libraries are missing, it should still:
  - show selector
  - explain what is needed to fully decode (ABI + decoder dependency)

---

## Example 3 — Encode a function call (ABI + arguments)

**Input**
- intent: "Create calldata for transfer(to=0xabc..., amount=1000000000000000000)."
- abi: |
  [
    {
      "type": "function",
      "name": "transfer",
      "stateMutability": "nonpayable",
      "inputs": [
        {"name": "to", "type": "address"},
        {"name": "amount", "type": "uint256"}
      ],
      "outputs": [{"name": "", "type": "bool"}]
    }
  ]

**Expected Output**
- Function selector
- Encoded calldata: `0x...`
- A warning:
  - This is **not** signed
  - Broadcasting requires a wallet
  - Confirm network/chain and contract address before sending

---

## Troubleshooting

### “RPC error / invalid response”
- Confirm `rpc_url` is correct and supports JSON-RPC.
- Confirm the tx hash exists on the selected chain.
- Try a different provider (or add an API key if required).

### “Cannot decode ABI”
- Ensure the ABI is valid JSON.
- Ensure the function exists in the ABI.
- Provide the correct calldata (must start with `0x`).

