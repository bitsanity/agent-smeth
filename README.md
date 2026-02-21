![agent-smeth](./agent-smeth.png)
# agent-smeth

An OpenClaw-friendly AI agent that enables humans and other agents to use Ethereum programmatically and conversationally.

---

## Overview

**agent-smeth** is an AI-powered Ethereum interaction layer. It allows users (and other AI agents) to:

* Interact with the Ethereum blockchain
* Execute transactions
* Query blockchain data
* Automate smart contract interactions
* Integrate Ethereum capabilities into agent-based systems

The goal is to simplify blockchain usage through intelligent agent abstraction.

---

## Features

* 🔑 QR code exchange with human to sign transactions. (see https://github.com/bitsanity/simpleth, https://github.com/bitsanity/ADILOS and https://github.com/bitsanity/adilosjs)
* 🔗 Default: connects to Ethereum using a local full node, or
* 🔌 Fallback: connects to Ethereum via Etherscan's API at https://etherscan.io (API key required)
* 💰 Agent can use its own Ethereum wallet, make smart contract calls and spend its own funds
* 🧾 Smart contract calls & transactions
* 📊 Blockchain data queries
* 🤖 Agent-to-agent Ethereum operations
* 🧠 AI-assisted transaction construction
* 🔐 Secure key handling architecture (implementation-dependent)

---

## Installation

1. Install OpenClaw from https://openclaw.ai (requires Node.js)
2. Configure OpenClaw to connect to an AI engine of your choice
3. Install `zbar-tools`
4. Install `qrencode`
5. Add the `agent-smeth` skill to your OpenClaw environment

On the human smartphone:
1. Install SIMPLETH or any ADILOS-compatible wallet app

### Clone the repository

```bash
git clone https://github.com/bitsanity/agent-smeth.git
cd agent-smeth
```

### Install dependencies

```bash
curl -fsSL https://openclaw.ai/install.sh | bash
sudo apt-get install zbar-tools qrencode
npm install web3js adilosjs
```

Note: `agent-smeth` uses `adilosjs` to generate cryptographic challenges and parse replies to verify the caller's pubkey and to obtain signatures.

---

## Startup Checks

On startup, `agent-smeth` performs dependency checks before handling intents:

- `zbar-tools` binaries (`zbarimg`/`zbarcam`) must be available
- `qrencode` binary must be available
- `adilosjs` must be resolvable by Node.js (`require.resolve('adilosjs')`)

If either check fails, the action returns a clear startup-check error with details in `data.startup_check`.

### Quick verification

```bash
python3 -m unittest tests/test_startup_checks.py
```

---

## Usage

### Example (Human-Agent or Agent-Agent Interaction)

```
find alice.eth in ENS
```

or

```
{ ens: "alice.eth" }
```

agent-smeth replies:

```
{ name: 'alice.eth', result: {ens result} }
```

---

### Example (Human-Agent or Agent-Agent Interaction)

```
"what is the current price of Ethereum"
```

or

```
{ price: true }
```

agent-smeth:
1. consults Etherscan.io
2. replies:
```
{ price: 4242.69 USD, today: "-2.73%", gasprice: 0.1 gwei }
```

---

### Example (CLI Human-Agent Interaction)

```
send 0.01 ETH from the agent wallet to 0xRecipientAddress
```

or

```
{ amount: '1337 finney', to: 0xRecipientAddress }
```

agent-smeth:

1. parses the instruction
2. fetches agent-smeth's account current nonce from Ethereum
3. fetches the current gas price from Ethereum
4. estimates the gas limit for a send transaction using Ethereum
5. confirms agent-smeth has enough balance to do the transaction
6. constructs the appropriate Ethereum transaction
7. signs the transaction using agent-smeth's private key
8. broadcasts the transaction to Ethereum and receives 0xEthereumTransactionId
9. replies:
```
{ txid: 0xEthereumTransactionId }
```

---

### Example (Agent-Agent Interaction)

```
{ amount: 100.0, token: "USDT", from: "alice.eth", to: 0xRecipientAddress }
```

agent-smeth:

1. parses the instruction
2. fetches the Ethereum address for alice.eth from ENS to obtain 0xAliceAddress
3. fetches the current nonce value for 0xAliceAddress from Ethereum
4. fetches the current gas price and estimated gas limit for the transaction from Ethereum
5. forms an ERC20-transfer transaction calling the USDT smart contract to transfer the tokens as instructed
6. creates an unsigned raw transaction U
7. replies
```  
"{ from: 0xAliceAddress unsignedtx: U }"
```

Alice-agent:

1. uses Alice's private key and signs U to generate digital signature S
2. replies
```
{ unsignedtx: U, signature: S }
```

agent-smeth:

1. appends Alice-agent's digital signature S to transaction U to form a complete Ethereum transaction
2. broadcasts the transaction to Ethereum and receives transaction id 0xEthereumTransactionId
3. replies
```
{ txid: 0xEthereumTransactionId } or { error: "... error message ..." }
```

---

### Example (Human-Agent Interaction)

```
"show me a qr code at the command line that says Hello World"
```

or

```
"say Hello World with a qr code"
```

agent-smeth:

1. extracts the message text
2. runs `qrencode -o /tmp/agent-smeth-qr-*.png "$MESSAGE"`
3. returns a PNG path for reliable scanning across terminals/UIs

---

### Example (Human-Agent Interaction)

```
"Verify my Ethereum account"
```

or

```
{ verify-account: true }
```

agent-smeth:

1. parses the instruction
2. generates an ADILOS challenge (see https://github.com/bitsanity/ADILOS)
3. presents the challenge to the human as a QR code

Human:

1. Runs the SIMPLETH mobile app to scan the challenge and create an Identification response as a QR code
2. Shows the Identification response to the camera

agent-smeth:

1. Uses the camera to scan the human's response QR code
2. Parses the QR code
3. Determines the Verified Account public key and Ethereum address
4. Performs a reverse-lookup in ENS to determine if the address has a name
5. replies
```
{
  hello: 0xVerifiedAccountAddress,
  ens: 'bitsanity.eth',
  balance: 0.01,
  nonce: 3
}
```

result: agent-smeth knows the human's Verified Account and ENS-name for use in future transactions

---

### Example (Human-Agent Interaction)

```
"send 0.01 ETH from Verified Account to 0xRecipientAddress"
```

agent-smeth:

1. parses the instruction
2. performs the verify interaction if necessary to know the Verified Account
3. fetches the Verified Account nonce, the Ethereum gas price and estimated gas limit
4. constructs the appropriate Ethereum transaction
5. generates and presents a hashed transaction to the user shown as a QR code
6. uses the camera to obtain the user's digital signature shown as a QR code
7. adds the user's digital signature to the transaction data
8. broadcasts the transaction to Ethereum

---
## Configuration

Common configuration options may include:

* `RPC_URL` – Recommended, Local Ethereum node, default ```ws://127.0.0.1:8546```
* `ETHERSCAN_API_URL` - Etherscan API URL default ```https://api.etherscan.io/v2/api/```
* `ETHERSCAN_API_KEY` - Required to use the Etherscan API
* `HUMAN_PUB_KEY` - Optional Human's Ethereum public key to avoid repeating the Verification exchange
* `PRIVATE_KEY` – Optional Agent wallet private key (use environment variables)
* `NETWORK` – mainnet, sepolia, etc.
* `GAS_STRATEGY` – automatic or manual gas settings

Example:

```bash
export RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY
export PRIVATE_KEY=your_private_key_here
```

---

## Architecture

agent-smeth can function as:

* A standalone Ethereum AI agent
* A plugin/tool for larger agent frameworks
* A microservice exposing Ethereum capabilities
* A composable module in multi-agent systems

---

## Security Notes

* Never commit private keys.
* Always use environment variables for secrets.
* Consider hardware wallets or signing abstractions for production.
* Test on testnets before using mainnet funds.

---

## Roadmap

* [✅] Ethereum Name Service (ENS) integration
* [ ] Stealth-Payment integration (agent can send and retrieve stealth payments)
* [ ] Multi-chain support
* [ ] ERC-20 / ERC-721 helpers
* [ ] Smart contract deployment support
* [ ] Natural language transaction validation
* [ ] Agent-to-agent trust model

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Submit a pull request

Please include clear descriptions and test coverage where applicable.

---

## License

This project is licensed under the Apache 2.0 License.

See the `LICENSE` file for details.

---

