// Unit tests for the plain logic in static/js/notarize.js. Run: node check_notarize_js.js
// (Needs only node; no packages. The page wiring itself needs a real browser.)
const assert = require("assert");
const n = require("./static/js/notarize.js");

let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log("[ OK ] " + name); }

const H = "ab".repeat(32);

// ---- toBytes32: the exact value handed to the contract --------------
test("toBytes32 adds 0x and keeps 32 bytes", () => {
  assert.strictEqual(n.toBytes32(H), "0x" + H);
  assert.strictEqual(n.toBytes32(H).length, 66);
});
test("toBytes32 lowercases and accepts an existing 0x", () => {
  assert.strictEqual(n.toBytes32("0x" + H.toUpperCase()), "0x" + H);
});
for (const [label, bad] of [["too short", "abcd"], ["too long", H + "00"], ["non-hex", "zz".repeat(32)],
                            ["empty", ""], ["null", null], ["number", 123]]) {
  test("toBytes32 rejects " + label, () => {
    assert.throws(() => n.toBytes32(bad), (e) => e.friendly === true);
  });
}

// ---- decideVerification: the VERIFIED / TAMPERED call ----------------
const rec = { exists: true, owner: "0xAbC0000000000000000000000000000000000001", timestamp: 1 };
test("same fingerprint + record exists -> VERIFIED", () => {
  assert.strictEqual(n.decideVerification(H, H, rec).state, "VERIFIED");
});
test("comparison ignores hex case", () => {
  assert.strictEqual(n.decideVerification(H, H.toUpperCase(), rec).state, "VERIFIED");
});
test("file changed (one hex digit) -> TAMPERED", () => {
  const changed = H.slice(0, -1) + "c";
  assert.strictEqual(n.decideVerification(H, changed, rec).state, "TAMPERED");
});
test("no record on chain -> MISSING (never VERIFIED)", () => {
  assert.strictEqual(n.decideVerification(H, H, { exists: false }).state, "MISSING");
  assert.strictEqual(n.decideVerification(H, H, null).state, "MISSING");
  assert.strictEqual(n.decideVerification(H, H, undefined).state, "MISSING");
});
test("missing record wins even if the file also changed", () => {
  assert.strictEqual(n.decideVerification(H, "00".repeat(32), { exists: false }).state, "MISSING");
});
test("owner matches regardless of case -> still VERIFIED", () => {
  assert.strictEqual(n.decideVerification(H, H, rec, rec.owner.toLowerCase()).state, "VERIFIED");
});
test("different owner than expected -> OWNER_MISMATCH, not VERIFIED", () => {
  const other = "0x" + "99".repeat(20);
  assert.strictEqual(n.decideVerification(H, H, rec, other).state, "OWNER_MISMATCH");
});
test("no expected owner given -> owner is not checked", () => {
  assert.strictEqual(n.decideVerification(H, H, rec, null).state, "VERIFIED");
});

// ---- explainError: kind messages, no raw stack traces ----------------
test("wallet rejection (EIP-1193 code 4001)", () => {
  assert.match(n.explainError({ code: 4001, message: "x" }), /cancelled/i);
});
test("wallet rejection (ethers ACTION_REJECTED)", () => {
  assert.match(n.explainError({ code: "ACTION_REJECTED" }), /cancelled/i);
});
test("wallet rejection (message text)", () => {
  assert.match(n.explainError(new Error("MetaMask Tx Signature: User denied transaction signature.")), /cancelled/i);
});
test("contract revert 'Already registered'", () => {
  assert.match(n.explainError({ reason: "Already registered" }), /already recorded/i);
});
test("insufficient funds points to a faucet", () => {
  assert.match(n.explainError({ code: "INSUFFICIENT_FUNDS" }), /faucet/i);
  assert.match(n.explainError(new Error("insufficient funds for gas")), /faucet/i);
});
test("network trouble", () => {
  assert.match(n.explainError({ code: "NETWORK_ERROR" }), /reach the blockchain/i);
  assert.match(n.explainError(new TypeError("Failed to fetch")), /reach the blockchain/i);
});
test("our own friendly errors pass through unchanged", () => {
  assert.strictEqual(n.explainError(n.friendly("Exactly this.")), "Exactly this.");
});
test("unknown errors are shortened, never a giant dump", () => {
  const out = n.explainError(new Error("x".repeat(5000)));
  assert.ok(out.length < 220, "too long: " + out.length);
});
test("explainError survives null / undefined / strings", () => {
  for (const v of [null, undefined, "boom", 42, {}]) assert.strictEqual(typeof n.explainError(v), "string");
});

// ---- shortAddress ----------------------------------------------------
test("shortAddress shortens a wallet and tolerates junk", () => {
  assert.strictEqual(n.shortAddress("0x" + "ab".repeat(20)), "0xabab…abab");
  assert.strictEqual(n.shortAddress(""), "");
  assert.strictEqual(n.shortAddress(null), "");
});

// ---- badgeFor: the badge after a Verify (Step 26) -------------------
test("badgeFor: only VERIFIED says Verified", () => {
  assert.deepStrictEqual(n.badgeFor("VERIFIED"), { kind: "pass", icon: "success", label: "Verified" });
  for (const s of ["TAMPERED", "MISSING", "OWNER_MISMATCH", "", undefined]) {
    assert.notStrictEqual(n.badgeFor(s).label, "Verified");
  }
});
test("badgeFor: TAMPERED is a danger badge, unknown states are cautions", () => {
  assert.strictEqual(n.badgeFor("TAMPERED").kind, "danger");
  assert.strictEqual(n.badgeFor("TAMPERED").label, "Tampered");
  assert.strictEqual(n.badgeFor("MISSING").kind, "warning");
  assert.strictEqual(n.badgeFor("OWNER_MISMATCH").kind, "warning");
});

console.log("\nAll " + passed + " checks passed.");
