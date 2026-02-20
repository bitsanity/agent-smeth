"""
agent-smeth OpenClaw action

Aligned with upstream README:
- Default local node / RPC preference
- Etherscan fallback
- ENS / price / tx inspection
- Unsigned transaction construction
- QR/verification flow hooks (platform-dependent)

Safety:
- Never request seed phrases.
- Refuse if secret material is pasted.
- Never silently broadcast transactions.

Dependencies: stdlib only.
Limitations:
- JSON-RPC here supports HTTP(S) endpoints only (not ws://).
- Full ENS resolution and ERC20 calldata encoding require additional config/deps.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


# ---------------------------
# Utilities / Safety
# ---------------------------

_SECRET_PATTERNS = [
    re.compile(r"\bseed phrase\b", re.IGNORECASE),
    re.compile(r"\bmnemonic\b", re.IGNORECASE),
    re.compile(r"\bprivate key\b", re.IGNORECASE),
    re.compile(r"BEGIN\s+PRIVATE\s+KEY", re.IGNORECASE),
    # naive hex private key-ish detector (64 hex chars)
    re.compile(r"\b0x[a-f0-9]{64}\b", re.IGNORECASE),
]


def _refuse_if_secret_present(inputs: Dict[str, Any]) -> Optional[str]:
    for _, v in inputs.items():
        if isinstance(v, str):
            for pat in _SECRET_PATTERNS:
                if pat.search(v):
                    return (
                        "Security warning: it looks like secret key material may have been provided. "
                        "Do NOT share private keys or seed phrases. I can’t process that. "
                        "Please remove it and retry with only public information (tx hash, address, calldata, ABI)."
                    )
    return None


def _as_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)


# ---------------------------
# JSON-RPC (HTTP only)
# ---------------------------

def _jsonrpc(rpc_url: str, method: str, params: list[Any], timeout_s: int = 20) -> Any:
    if rpc_url.startswith("ws://") or rpc_url.startswith("wss://"):
        raise RuntimeError("This action only supports HTTP(S) JSON-RPC endpoints (not ws://).")

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
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

    if out.get("error"):
        raise RuntimeError(f"JSON-RPC error: {out['error']}")
    return out.get("result")


def _hex_to_int(x: Optional[str]) -> Optional[int]:
    if x is None:
        return None
    if isinstance(x, str) and x.startswith("0x"):
        return int(x, 16)
    return None


def _int_to_hex(n: int) -> str:
    return hex(n)


# ---------------------------
# Etherscan (fallback)
# ---------------------------

def _etherscan_get(api_url: str, api_key: str, params: Dict[str, str], timeout_s: int = 20) -> Dict[str, Any]:
    q = dict(params)
    q["apikey"] = api_key

    base = api_url.rstrip("/")
    if base.endswith("/api"):
        url = base + "?" + urllib.parse.urlencode(q)
    else:
        url = base + "/api?" + urllib.parse.urlencode(q)

    with urllib.request.urlopen(url, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)


# ---------------------------
# Intent routing
# ---------------------------

def _looks_like_ens(name: str) -> bool:
    return isinstance(name, str) and "." in name and name.lower().endswith(".eth")


def _normalize_amount(amount: str) -> Dict[str, Any]:
    """
    Minimal parser for README-style amounts:
    - "0.01 ETH"
    - "1337 finney"
    Returns a dict with best-effort wei or notes.
    """
    a = amount.strip()
    m = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*(eth|ether)\s*$", a, re.IGNORECASE)
    if m:
        val = float(m.group(1))
        wei = int(val * 10**18)
        return {"unit": "ETH", "value": val, "wei": wei}

    m = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*finney\s*$", a, re.IGNORECASE)
    if m:
        val = float(m.group(1))
        wei = int(val * 10**15)
        return {"unit": "finney", "value": val, "wei": wei}

    # fallback: unknown
    return {"raw": amount, "note": "Could not parse amount into wei. Provide like '0.01 ETH' or '1337 finney'."}


# ---------------------------
# Main action entrypoint
# ---------------------------

def run(
    intent: str,
    chain: str = "mainnet",
    rpc_url: Optional[str] = None,
    etherscan_api_url: Optional[str] = None,
    etherscan_api_key: Optional[str] = None,
    from_: Optional[str] = None,
    to: Optional[str] = None,
    amount: Optional[str] = None,
    token: Optional[str] = None,
    tx_hash: Optional[str] = None,
    payload: Optional[str] = None,
) -> Dict[str, Any]:
    # Pull defaults from env to match README config section
    rpc_url = rpc_url or os.getenv("RPC_URL") or "ws://127.0.0.1:8546"
    etherscan_api_url = etherscan_api_url or os.getenv("ETHERSCAN_API_URL") or "https://etherscan.io"
    etherscan_api_key = etherscan_api_key or os.getenv("ETHERSCAN_API_KEY")

    inputs = {
        "intent": intent,
        "chain": chain,
        "rpc_url": rpc_url,
        "etherscan_api_url": etherscan_api_url,
        "etherscan_api_key": etherscan_api_key,
        "from": from_,
        "to": to,
        "amount": amount,
        "token": token,
        "tx_hash": tx_hash,
        "payload": payload,
    }

    secret_refusal = _refuse_if_secret_present(inputs)
    if secret_refusal:
        return {"response": secret_refusal, "data": {"refused": True}}

    data_out: Dict[str, Any] = {
        "chain": chain,
        "sources": [],
    }

    # Optional structured payload
    payload_obj: Optional[dict] = None
    if payload:
        try:
            payload_obj = json.loads(payload)
            data_out["payload"] = payload_obj
        except Exception as e:
            data_out["payload_error"] = f"payload JSON parse error: {e}"

    intent_l = intent.lower()

    # ---------------------------
    # 1) Gas price (RPC or Etherscan)
    # ---------------------------
    if "gas price" in intent_l or "gasprice" in intent_l:
        # Prefer RPC if a HTTP(S) URL is provided; fall back to Etherscan if configured
        if rpc_url and not rpc_url.startswith("ws://") and not rpc_url.startswith("wss://"):
            try:
                gas_hex = _jsonrpc(rpc_url, "eth_gasPrice", [])
                data_out["sources"].append("rpc:eth_gasPrice")
                gas_wei = _hex_to_int(gas_hex)
                gas_gwei = (gas_wei / 10**9) if gas_wei is not None else None
                return {
                    "response": "Fetched current gas price via JSON-RPC.",
                    "data": {**data_out, "gas": {"wei": gas_wei, "gwei": gas_gwei}},
                }
            except Exception as e:
                data_out["rpc_error"] = str(e)

        if etherscan_api_key:
            try:
                params = {"module": "gastracker", "action": "gasoracle"}
                if "/v2/" in (etherscan_api_url or ""):
                    chainid_map = {"mainnet": "1", "sepolia": "11155111", "holesky": "17000"}
                    params["chainid"] = chainid_map.get(chain, "1")

                resp = _etherscan_get(etherscan_api_url, etherscan_api_key, params)
                data_out["sources"].append("etherscan:gastracker.gasoracle")
                data_out["gasoracle_raw"] = resp
                result = resp.get("result", {}) if isinstance(resp, dict) else {}
                propose = result.get("ProposeGasPrice") if isinstance(result, dict) else None
                safe = result.get("SafeGasPrice") if isinstance(result, dict) else None
                fast = result.get("FastGasPrice") if isinstance(result, dict) else None
                return {
                    "response": "Fetched current gas price via Etherscan gas oracle.",
                    "data": {**data_out, "gas": {"gwei": propose, "safe": safe, "fast": fast}},
                }
            except Exception as e:
                data_out["etherscan_error"] = str(e)

        return {
            "response": (
                "I couldn’t fetch gas price. Provide an HTTP(S) rpc_url or configure Etherscan "
                "(etherscan_api_key / ETHERSCAN_API_KEY)."
            ),
            "data": data_out,
        }

    # ---------------------------
    # 2) Price query (Etherscan fallback)
    # ---------------------------
    if "price" in intent_l and (
        "ethereum" in intent_l or re.search(r"\beth\b", intent_l) or "agent-smeth" in intent_l
    ):
        # Prefer Etherscan because it's simple and matches README example
        if etherscan_api_key:
            try:
                params = {"module": "stats", "action": "ethprice"}
                # v2 endpoints require chainid
                if "/v2/" in (etherscan_api_url or ""):
                    chainid_map = {"mainnet": "1", "sepolia": "11155111", "holesky": "17000"}
                    params["chainid"] = chainid_map.get(chain, "1")

                resp = _etherscan_get(
                    etherscan_api_url,
                    etherscan_api_key,
                    params,
                )
                data_out["sources"].append("etherscan:stats.ethprice")
                data_out["ethprice_raw"] = resp
                # best-effort extraction
                result = resp.get("result", {}) if isinstance(resp, dict) else {}
                price_usd = result.get("ethusd") if isinstance(result, dict) else None
                out_obj = {"price_usd": price_usd, "note": "Gas price is network-dependent; use RPC for live gas price."}
                return {
                    "response": "Fetched ETH price via Etherscan (fallback path).",
                    "data": {**data_out, "price": out_obj},
                }
            except Exception as e:
                data_out["etherscan_error"] = str(e)

        return {
            "response": (
                "I couldn’t fetch ETH price because Etherscan is not configured (missing ETHERSCAN_API_KEY) "
                "or the request failed. Provide etherscan_api_key (or set env ETHERSCAN_API_KEY), "
                "or provide an HTTP(S) rpc_url to query chain data."
            ),
            "data": data_out,
        }

    # ---------------------------
    # 3) Explain transaction (RPC)
    # ---------------------------
    if ("explain" in intent_l or "receipt" in intent_l or "transaction" in intent_l) and tx_hash:
        try:
            tx = _jsonrpc(rpc_url, "eth_getTransactionByHash", [tx_hash])
            rcpt = _jsonrpc(rpc_url, "eth_getTransactionReceipt", [tx_hash])
            data_out["sources"].append("rpc:eth_getTransactionByHash,eth_getTransactionReceipt")
            data_out["tx"] = tx
            data_out["receipt"] = rcpt

            summary = {
                "from": (tx or {}).get("from") if isinstance(tx, dict) else None,
                "to": (tx or {}).get("to") if isinstance(tx, dict) else None,
                "value_wei": _hex_to_int((tx or {}).get("value")) if isinstance(tx, dict) else None,
                "status": (rcpt or {}).get("status") if isinstance(rcpt, dict) else None,
                "gas_used": _hex_to_int((rcpt or {}).get("gasUsed")) if isinstance(rcpt, dict) else None,
                "logs_count": len((rcpt or {}).get("logs", [])) if isinstance(rcpt, dict) else None,
            }
            return {"response": "Fetched transaction + receipt via JSON-RPC.", "data": {**data_out, "summary": summary}}
        except Exception as e:
            return {
                "response": f"RPC tx lookup failed. If your default is ws://127.0.0.1:8546, provide an HTTP(S) rpc_url. Error: {e}",
                "data": data_out,
            }

    # ---------------------------
    # 3) ENS lookup (placeholder unless ENS contracts configured)
    # ---------------------------
    if ("ens" in intent_l or "find" in intent_l) and (
        from_ and _looks_like_ens(from_) or to and _looks_like_ens(to) or ".eth" in intent_l
    ):
        return {
            "response": (
                "ENS resolution requires calling the ENS registry/resolver contracts via RPC (eth_call) "
                "and knowing the ENS registry address for the target chain. "
                "This action is currently configured as a placeholder; provide/implement ENS_REGISTRY_ADDRESS "
                "and resolver logic (or add a dependency like web3.py) to fully resolve .eth names."
            ),
            "data": {**data_out, "ens": {"note": "placeholder", "requested_from": from_, "requested_to": to}},
        }

    # ---------------------------
    # 4) Build unsigned ETH transfer tx (nonce + gas price)
    # ---------------------------
    if ("build" in intent_l or "construct" in intent_l or "create" in intent_l) and ("send" in intent_l or "transfer" in intent_l) and to and amount and (token is None):
        amt = _normalize_amount(amount)
        unsigned = {
            "to": to,
            "value": _int_to_hex(amt["wei"]) if "wei" in amt else None,
            "data": "0x",
        }

        # Try to enrich with nonce + gas price if we can
        # Note: from may be missing; if so, we return tx skeleton
        if from_ and re.fullmatch(r"0x[a-fA-F0-9]{40}", from_):
            try:
                nonce_hex = _jsonrpc(rpc_url, "eth_getTransactionCount", [from_, "latest"])
                gasprice_hex = _jsonrpc(rpc_url, "eth_gasPrice", [])
                data_out["sources"].append("rpc:eth_getTransactionCount,eth_gasPrice")
                unsigned["nonce"] = nonce_hex
                unsigned["gasPrice"] = gasprice_hex
            except Exception as e:
                data_out["rpc_enrich_error"] = str(e)

        return {
            "response": (
                "Constructed an unsigned ETH transfer transaction object. "
                "Review carefully, then sign with a wallet or a dedicated signing agent. "
                "Broadcasting is irreversible."
            ),
            "data": {**data_out, "unsignedtx": unsigned, "amount_parsed": amt},
        }

    # ---------------------------
    # 5) ERC20 transfer (placeholder unless token address + encoder configured)
    # ---------------------------
    if token and ("erc20" in intent_l or "token" in intent_l or "transfer" in intent_l):
        return {
            "response": (
                "ERC-20 transfer construction requires the token contract address on this chain and "
                "calldata encoding for transfer(address,uint256). "
                "This action currently provides a placeholder. Add a token-address registry and an ABI encoder "
                "(e.g., eth-abi/eth-utils) to output the full unsignedtx."
            ),
            "data": {**data_out, "erc20": {"token": token, "from": from_, "to": to, "amount": amount, "note": "placeholder"}},
        }

    # ---------------------------
    # 6) Verification / QR flow hook (ADILOS + SIMPLETH)
    # ---------------------------
    if "verify" in intent_l and "account" in intent_l:
        return {
            "response": (
                "Verification flow (ADILOS + QR) is platform-dependent. "
                "High-level steps: generate an ADILOS challenge; display as QR; user signs/responds via SIMPLETH; "
                "scan response QR; derive verified pubkey/address; optionally reverse-lookup ENS."
            ),
            "data": {**data_out, "verify_flow": {"challenge": "platform-dependent", "note": "hook"}},
        }

    # Default: return a concise “what I can do + what’s missing”
    return {
        "response": (
            "I can help with ETH price (Etherscan), tx explanation (RPC), and building unsigned tx objects. "
            "For full ENS resolution, ERC-20 calldata building, QR signing, and broadcast/signing, additional "
            "runtime integrations are needed (ENS contract addresses, ABI encoder, camera/QR IO, and signer)."
        ),
        "data": data_out,
    }
