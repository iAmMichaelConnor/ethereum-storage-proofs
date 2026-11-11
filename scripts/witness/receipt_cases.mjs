// Independent EthereumJS receipt tries: one receipt per case at a chosen index, with
// typed, historical, failed, multi-log and long-data receipts. No verifier code builds them.
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";

const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const integer = (n) => {
  n = BigInt(n);
  if (!n) return new Uint8Array();
  let s = n.toString(16);
  if (s.length % 2) s = "0" + s;
  return Uint8Array.from(Buffer.from(s, "hex"));
};

function receipt(type = 0, logCount = 2, dataLength = 56, historical = false, success = true, topics = 2) {
  const logs = Array.from({ length: logCount }, (_, i) => [
    new Uint8Array(20).fill(i + 1),
    Array.from({ length: i === 0 ? 0 : topics }, (_, j) => new Uint8Array(32).fill(j + 2)),
    new Uint8Array(i === 0 ? 0 : dataLength).fill(0xa5),
  ]);
  const bloom = new Uint8Array(256);
  for (const [address, topics] of logs)
    for (const value of [address, ...topics]) {
      const h = keccak256(value);
      for (let i = 0; i < 6; i += 2) {
        const bit = ((h[i] << 8) | h[i + 1]) & 2047;
        bloom[255 - (bit >> 3)] |= 1 << (bit & 7);
      }
    }
  const payload = RLP.encode([
    historical ? new Uint8Array(32).fill(7) : integer(success ? 1 : 0),
    integer((1n << 64n) - 1n),
    bloom,
    logs,
  ]);
  return type ? Uint8Array.from([type, ...payload]) : payload;
}
async function receiptCase(name, keys, index, value, logIndex = 0) {
  const trie = new Trie({ useKeyHashing: false });
  for (const k of keys) await trie.put(RLP.encode(integer(k)), k === index ? value : receipt(2, 0));
  return {
    name,
    input: {
      receiptsRoot: hex(trie.root()),
      transactionIndex: String(index),
      receipt: hex(value),
      proof: (await trie.createProof(RLP.encode(integer(index)))).map(hex),
      logIndex,
    },
  };
}
export async function receiptCases() {
  const cases = [];
  for (const index of [0n, 1n, 127n, 128n, 255n, 256n, 65535n, 65536n, (1n << 64n) - 1n])
    cases.push(await receiptCase("leaf_index_" + index, [index], index, receipt(0, 0)));
  cases.push(await receiptCase("historical", [0n], 0n, receipt(0, 1, 0, true)));
  cases.push(await receiptCase("failed", [0n], 0n, receipt(0, 0, 0, false, false)));
  for (const type of [1, 2, 3, 4])
    cases.push(await receiptCase("typed_" + type, [0n, 1n, 2n], 1n, receipt(type, 2, 56, false, true, 4), 1));
  cases.push(await receiptCase("extension", [256n, 257n], 256n, receipt(2, 2, 55), 1));
  cases.push(await receiptCase("empty_event", [0n, 1n], 0n, receipt(0, 1)));
  cases.push(await receiptCase("long_data", [127n, 128n, 129n], 128n, receipt(3, 3, 256), 2));
  return cases;
}
