// src/protocol.ts
function leadingZeroBits(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let n = 0;
  for (const c of b) {
    if (c === 0) {
      n += 8;
      continue;
    }
    for (let i = 7; i >= 0; i--) {
      if ((c & 1 << i) === 0) n++;
      else return n;
    }
  }
  return n;
}
async function hashSHA256Solution(challenge, solution) {
  const enc = new TextEncoder();
  const nonce = enc.encode(challenge);
  const colon = enc.encode(":");
  const num = new ArrayBuffer(8);
  new DataView(num).setBigUint64(0, BigInt(solution), false);
  const body = new Uint8Array(nonce.length + colon.length + 8);
  body.set(nonce, 0);
  body.set(colon, nonce.length);
  body.set(new Uint8Array(num), nonce.length + colon.length);
  return crypto.subtle.digest("SHA-256", body);
}
async function verifySHA256(challenge, solution, difficulty) {
  const digest = await hashSHA256Solution(challenge, solution);
  return leadingZeroBits(digest) >= difficulty;
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
async function verifyPBKDF2(challenge, saltHex, solution, difficulty, iterations) {
  const password = new TextEncoder().encode(`${challenge}:${solution}`);
  const saltBytes = hexToBytes(saltHex);
  const salt = saltBytes.buffer.slice(
    saltBytes.byteOffset,
    saltBytes.byteOffset + saltBytes.byteLength
  );
  const key = await crypto.subtle.importKey("raw", password, "PBKDF2", false, [
    "deriveBits"
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );
  return leadingZeroBits(bits) >= difficulty;
}

// src/workers/pbkdf2.ts
async function scan(req) {
  const ch = req.challenge;
  const iters = ch.params?.iterations ?? 1e4;
  try {
    for (let i = req.start; i <= req.end; i++) {
      let ok = false;
      if (ch.algorithm === "PBKDF2-SHA256") {
        if (!ch.salt) return { id: req.id, done: true, error: "missing salt" };
        ok = await verifyPBKDF2(ch.challenge, ch.salt, i, ch.difficulty, iters);
      } else {
        ok = await verifySHA256(ch.challenge, i, ch.difficulty);
      }
      if (ok) return { id: req.id, found: i, done: true };
    }
    return { id: req.id, done: true };
  } catch (e) {
    return {
      id: req.id,
      done: true,
      error: e instanceof Error ? e.message : String(e)
    };
  }
}
self.onmessage = (ev) => {
  void scan(ev.data).then((res) => self.postMessage(res));
};
//# sourceMappingURL=pbkdf2.js.map
//# sourceMappingURL=pbkdf2.js.map