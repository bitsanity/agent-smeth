# agent-smeth — Example Usage (OpenClaw Skill)

These examples mirror the upstream README behaviors: ENS lookup, price query via Etherscan fallback, ETH send flow, agent-to-agent unsigned tx flow, and verification/QR flow hooks.

> Safety: This skill never asks for seed phrases. Broadcasting is irreversible—always double-check chain, addresses, and amounts.

---

## 1) ENS lookup

**Input**
- intent: "find alice.eth in ENS"

**Expected**
- Resolve alice.eth -> 0x...
- Output a structured result object.

---

## 2) ETH price (Etherscan fallback)

**Input**
- intent: "what is the current price of Ethereum"
- etherscan_api_key: "YOUR_KEY"   (or set env ETHERSCAN_API_KEY)

**Expected**
- Uses Etherscan if RPC is not available.
- Returns `{ price_usd, gasprice_gwei (if available) }`.

---

## 3) Explain a transaction (RPC)

**Input**
- intent: "explain this transaction"
- rpc_url: "https://YOUR-RPC"
- tx_hash: "0x..."

**Expected**
- Fetch tx + receipt via JSON-RPC.
- Summarize status, from/to, value, gas used, logs count.
- Provide raw tx/receipt in structured output.

---

## 4) Build an ETH transfer transaction (unsigned)

**Input**
- intent: "build a transaction to send 0.01 ETH to 0xRecipientAddress"
- rpc_url: "https://YOUR-RPC"
- to: "0xRecipientAddress"
- amount: "0.01 ETH"

**Expected**
- Fetch nonce + gas price (RPC).
- Construct an unsigned tx object.
- Return it as JSON for wallet signing.

---

## 5) Agent-to-agent ERC-20 transfer flow (unsigned tx handoff)

**Input**
- intent: "create an unsigned ERC20 transfer of 100 USDT from alice.eth to 0xRecipientAddress"
- rpc_url: "https://YOUR-RPC"
- from: "alice.eth"
- to: "0xRecipientAddress"
- amount: "100"
- token: "USDT"

**Expected**
- Resolve ENS -> from address.
- Build an unsigned tx skeleton:
  - to = token contract address (if known/configured)
  - data = ERC20 transfer calldata (if encoder available; otherwise explain what’s missing)
- Output `{ from, unsignedtx }` for a signing agent to sign.

---

## 6) Verification / QR flow (hook)

**Input**
- intent: "Verify my Ethereum account"

**Expected**
- Returns an instruction payload describing the QR challenge flow (ADILOS/SIMPLETH),
  or a placeholder explaining that QR camera IO is platform-dependent.

