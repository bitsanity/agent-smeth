User instruction:
{{intent}}

Parameters (may be empty):
- chain: {{chain}}
- rpc_url: {{rpc_url}}
- etherscan_api_url: {{etherscan_api_url}}
- etherscan_api_key: {{etherscan_api_key}}
- from: {{from}}
- to: {{to}}
- amount: {{amount}}
- token: {{token}}
- tx_hash: {{tx_hash}}
- payload: {{payload}}

Task:
- Interpret the instruction.
- If the action tool returned structured data, use it.
- If required configuration is missing, explain what to set (RPC_URL / ETHERSCAN_API_KEY) and what you can still do offline.
- For transactions:
  - If the user asked to build: return an unsigned transaction payload.
  - If the user asked to sign/broadcast: warn clearly; only proceed if explicitly requested and signing is enabled; otherwise provide instructions.

