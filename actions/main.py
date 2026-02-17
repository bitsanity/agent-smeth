"""
Agent Smeth - OpenClaw action entrypoint

This file is intentionally safe-by-default:
- It NEVER requests or processes private keys or seed phrases.
- It requires a human to sign transactions
- It may broadcast transactions through an Ethereum full node or public API
- It can optionally fetch public on-chain data via JSON-RPC if rpc_url is provided.

If you want full ABI encode/decode, install optional deps:
- eth-abi
- eth-utils
"""

from __future__ import annotations

import json
import textwrap
import urllib.request
import urllib.error
from typing import Any, Dict, Optional, Tuple


def _jsonrpc(rpc_url: str, method: str, params: list[Any], timeout_s: int = 20) -> Any:
    """Minimal JSON-RPC client using stdlib only."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        rpc_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        out = json.loads(raw)

    if "error" in out and out["error"] is not None:
        raise RuntimeError(f"JSON-RPC error: {out['error']}")
    return out.get("result")


def _safe_warn_if_secret_present(inputs: Dict[str, Any]) -> Optional[str]:
    """
    If user accidentally provided secret material in any text field, refuse.
    This is a lightweight heuristic; you can improve it as needed.
    """
    suspicious_markers = [
        "seed phrase",
        "mnemonic",
        "private key",
        "BEGIN PRIVATE KEY",
        "0x" + "a" * 64,  # simplistic marker; not a real key check
    ]
    for k, v in inputs.items():
        if isinstance(v, str):
            low = v.lower()
            if any(m in low for m in suspicious_markers):
                return (
                    "Security warning: it looks like secret key material may have been provided. "
                    "Do NOT share private keys or seed phrases. I can’t process or store that. "
                    "Please remove it and try again with only public information (tx hash, address, calldata, ABI)."
                )
    return None


def _selector(calldata_hex: str) -> Optional[str]:
    """
    Return 4-byte selector hex string (0x????????) if calldata has at least 4 bytes.
    calldata_hex should be 0x-prefixed.
    """
    if not calldata_hex or not calldata_hex.startswith("0x"):
        return None
    hex_body = calldata_hex[2:]
    if len(hex_body) < 8:
        return None
    return "0x" + hex_body[:8]


def _try_decode_with_abi(abi_json_str: str, calldata_hex: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Best-effort calldata decoding if optional dependencies exist.
    Returns (decoded, error_message).
    """
    try:
        abi = json.loads(abi_json_str)
        if not isinstance(abi, list):
            return None, "ABI JSON must be a list of ABI items."
    except Exception as e:
        return None, f"ABI JSON parsing error: {e}"

    sel = _selector(calldata_hex)
    if not sel:
        return None, "Calldata is missing or too short to contain a function selector."

    # Optional deps
    try:
        from eth_utils import keccak  # type: ignore
        from eth_abi import decode as eth_abi_decode  # type: ignore
    except Exception:
        return None, (
            "Optional dependencies not installed for ABI decoding. "
            "Install 'eth-abi' and 'eth-utils' to enable full decoding."
        )

    # Find function by selector
    def func_selector(item: dict) -> Optional[str]:
        if item.get("type") != "function":
            return None
        name = item.get("name")
        inputs = item.get("inputs", [])
        if not isinstance(inputs, list) or not isinstance(name, str):
            return None
        sig = name + "(" + ",".join(inp.get("type", "") for inp in inputs) + ")"
        digest = keccak(text=sig)  # type: ignore
        return "0x" + digest.hex()[:8]

    fn_item = None
    for item in abi:
        if isinstance(item, dict) and func_selector(item) == sel:
            fn_item = item
            break

    if not fn_item:
        return None, f"No function in ABI matches selector {sel}."

    inputs = fn_item.get("inputs", [])
    types = [i.get("type") for i in inputs]
    names = [i.get("name") or f"arg{idx}" for idx, i in enumerate(inputs)]

    try:
        data_bytes = bytes.fromhex(calldata_hex[2:])[4:]  # strip selector
        decoded_vals = eth_abi_decode(types, data_bytes)  # type: ignore
    except Exception as e:
        return None, f"ABI decode error: {e}"

    decoded = {
        "selector": sel,
        "function": fn_item.get("name"),
        "signature": fn_item.get("name") + "(" + ",".join(types) + ")",
        "args": {names[i]: decoded_vals[i] for i in range(len(decoded_vals))},
    }
    return decoded, None


def run(
    intent: str,
    chain: str = "ethereum-mainnet",
    rpc_url: Optional[str] = None,
    address: Optional[str] = None,
    tx_hash: Optional[str] = None,
    abi: Optional[str] = None,
    data: Optional[str] = None,
) -> Dict[str, Any]:
    """
    OpenClaw action entrypoint.
    Return a dict that the skill runtime can pass back to the model / user.
    """
    inputs = {
        "intent": intent,
        "chain": chain,
        "rpc_url": rpc_url,
        "address": address,
        "tx_hash": tx_hash,
        "abi": abi,
        "data": data,
    }

    secret_warning = _safe_warn_if_secret_present(inputs)
    if secret_warning:
        return {"response": secret_warning, "data": {"refused": True}}

    notes: list[str] = []
    out: Dict[str, Any] = {"response": "", "data": {}}

    notes.append(f"Chain: {chain}")

    # 1) If RPC + tx_hash, fetch tx + receipt
    if rpc_url and tx_hash:
        try:
            tx = _jsonrpc(rpc_url, "eth_getTransactionByHash", [tx_hash])
            receipt = _jsonrpc(rpc_url, "eth_getTransactionReceipt", [tx_hash])
            out["data"]["tx"] = tx
            out["data"]["receipt"] = receipt

            if tx is None:
                notes.append("Transaction not found on this RPC/chain for the given tx_hash.")
            else:
                notes.append("Fetched transaction via JSON-RPC.")
            if receipt is None:
                notes.append("Receipt not found yet (tx may be pending) or RPC does not have it.")
            else:
                notes.append("Fetched receipt via JSON-RPC.")
        except urllib.error.URLError as e:
            notes.append(f"RPC network error: {e}")
        except Exception as e:
            notes.append(f"RPC error: {e}")

    # 2) If calldata present, extract selector
    if data and isinstance(data, str) and data.startswith("0x"):
        sel = _selector(data)
        if sel:
            out["data"]["selector"] = sel
            notes.append(f"Detected function selector: {sel}")

    # 3) If ABI + calldata, try decode
    if abi and data:
        decoded, err = _try_decode_with_abi(abi, data)
        if decoded:
            out["data"]["decoded_calldata"] = decoded
            notes.append("Decoded calldata using provided ABI.")
        else:
            notes.append(f"Could not decode calldata: {err}")

    # 4) Compose human-readable response (safe summary)
    summary_lines = [
        "Agent Smeth (safe mode): I can help analyze and prepare Ethereum interactions, but I do not sign or broadcast transactions.",
        "",
        "What I understood:",
        f"- Intent: {intent}",
        f"- Chain: {chain}",
    ]
    if address:
        summary_lines.append(f"- Address: {address}")
    if tx_hash:
        summary_lines.append(f"- Tx hash: {tx_hash}")
    if rpc_url:
        summary_lines.append("- RPC: provided")
    if data:
        summary_lines.append(f"- Data: provided ({len(data)} chars)")
    if abi:
        summary_lines.append("- ABI: provided")

    summary_lines.append("")
    summary_lines.append("Notes / Results:")
    summary_lines.extend([f"- {n}" for n in notes])

    # Broadcasting warning when intent implies sending
    sending_keywords = ["send", "broadcast", "submit", "sign", "transfer", "swap", "approve"]
    if any(k in intent.lower() for k in sending_keywords):
        summary_lines.append("")
        summary_lines.append(
            "Warning: Broadcasting a transaction is irreversible. This skill does not sign or broadcast transactions. "
            "Use a wallet to sign and submit, and double-check chain, contract address, amounts, and gas settings."
        )

    out["response"] = "\n".join(summary_lines).strip()

    return out


# For local manual testing:
if __name__ == "__main__":
    demo = run(
        intent="Explain this transaction.",
        chain="ethereum-mainnet",
        rpc_url=None,
        tx_hash=None,
        abi=None,
        data="0xa9059cbb" + "00" * 32,
    )
    print(demo["response"])
    print(json.dumps(demo["data"], indent=2))

