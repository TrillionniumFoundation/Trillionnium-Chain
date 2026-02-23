import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as ed from '@noble/ed25519';

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';
const DENOM = process.env.DENOM || 'utrnm';
const FAUCET_AMOUNT = BigInt(process.env.FAUCET_AMOUNT || '1000000');
const TRANSFER_AMOUNT = BigInt(process.env.TRANSFER_AMOUNT || '1000');
const POLL_MS = Number(process.env.POLL_MS || '800');
const POLL_MAX = Number(process.env.POLL_MAX || '20');
const POLL_TIMEOUT_MS = Number(process.env.POLL_TIMEOUT_MS || String(POLL_MS * POLL_MAX));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function deriveAddressFromPubkey(pubkeyBytes) {
  const digest = sha256(pubkeyBytes);
  return `trnm1${bytesToHex(digest.slice(0, 20))}`;
}

function buildSigningMessage({ from, to, amount, fee, nonce }) {
  return `trnm-transfer-v1|from=${from}|to=${to}|amount=${amount}|fee=${fee}|nonce=${nonce}`;
}

async function createWallet() {
  // Rust side expects a 32-byte private key hex.
  const privateKey = randomBytes(32);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    address: deriveAddressFromPubkey(publicKey),
  };
}

async function signTransfer(tx, privateKeyHex, publicKeyHex) {
  const msg = new TextEncoder().encode(buildSigningMessage(tx));
  const sig = await ed.signAsync(msg, hexToBytes(privateKeyHex));
  return `ed25519:${publicKeyHex}:${bytesToHex(sig)}`;
}

async function rpc(method, params, id = 1) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }

  const body = await res.json();
  if (body.error) {
    const msg = body.error.message || JSON.stringify(body.error);
    throw new Error(`[${method}] ${msg}`);
  }
  return body.result;
}

async function callFaucet(address, amount) {
  const amountStr = amount.toString();
  const methods = ['faucetRequest', 'faucet'];
  let lastErr = null;

  for (const m of methods) {
    try {
      const result = await rpc(m, { address, amount: amountStr });
      return { method: m, result };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`faucet call failed on methods [${methods.join(', ')}]: ${lastErr?.message || 'unknown'}`);
}

async function pollTx(txHash) {
  let last = null;
  const startedAt = Date.now();
  for (let i = 0; i < POLL_MAX; i += 1) {
    last = await rpc('getTx', { txHash }, 100 + i);
    const status = String(last.status || '').toLowerCase();

    if (status === 'committed' || status === 'fail') {
      return last;
    }

    if (status !== 'pending') {
      throw new Error(`getTx returned unexpected status='${status}' for txHash=${txHash}, raw=${JSON.stringify(last)}`);
    }

    if (Date.now() - startedAt >= POLL_TIMEOUT_MS) {
      break;
    }
    await sleep(POLL_MS);
  }
  throw new Error(
    `getTx timeout waiting terminal status (expect committed/fail, got pending). txHash=${txHash}, pollMax=${POLL_MAX}, pollMs=${POLL_MS}, timeoutMs=${POLL_TIMEOUT_MS}, last=${JSON.stringify(last)}`,
  );
}

async function main() {
  console.log(`RPC_URL=${RPC_URL}`);

  // 1) create wallet
  const alice = await createWallet();
  const bob = await createWallet();
  console.log('[1/4] wallets created');
  console.log(`alice=${alice.address}`);
  console.log(`bob=${bob.address}`);

  // 2) faucet
  const faucet = await callFaucet(alice.address, FAUCET_AMOUNT);
  console.log(`[2/4] faucet ok via method=${faucet.method}`);
  console.log(JSON.stringify(faucet.result, null, 2));

  // 3) sendTx
  const balanceRes = await rpc('balance', { address: alice.address }, 21);
  const nonceRes = await rpc('nonce', { address: alice.address }, 22);

  const tx = {
    from: alice.address,
    to: bob.address,
    amount: TRANSFER_AMOUNT.toString(),
    fee: '0',
    denom: DENOM,
    nonce: Number(nonceRes.nonce),
  };

  const signature = await signTransfer(tx, alice.privateKeyHex, alice.publicKeyHex);
  const sendRes = await rpc('sendTx', { ...tx, signature }, 23);
  console.log('[3/4] sendTx accepted');
  console.log(JSON.stringify({ balance: balanceRes, nonce: nonceRes, sendTx: sendRes }, null, 2));

  // 4) getTx
  const txHash = sendRes.tx_hash || sendRes.txHash;
  if (!txHash) throw new Error(`sendTx missing tx hash: ${JSON.stringify(sendRes)}`);

  const receipt = await pollTx(txHash);
  const finalStatus = String(receipt.status || '').toLowerCase();
  if (finalStatus === 'pending') {
    throw new Error(`tx should be terminal but still pending, txHash=${txHash}, receipt=${JSON.stringify(receipt)}`);
  }
  if (!['committed', 'fail'].includes(finalStatus)) {
    throw new Error(`tx final status must be committed/fail, got='${finalStatus}', txHash=${txHash}`);
  }

  console.log('[4/4] getTx final (terminal)');
  console.log(JSON.stringify(receipt, null, 2));

  console.log('DONE: create wallet -> faucet -> sendTx -> getTx');
}

main().catch((err) => {
  console.error('quickstart failed:', err.message);
  process.exit(1);
});
