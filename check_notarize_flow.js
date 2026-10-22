// Runs the REAL static/js/notarize.js against a simulated page, wallet,
// ethers.js and server, to check the control flow: what is called, in what
// order, what is sent, and what the person sees. Run: node check_notarize_flow.js
//
// It cannot prove MetaMask or ethers behave as simulated — that needs a
// browser and a wallet. It does catch ordering, argument and messaging bugs.
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

const SRC = fs.readFileSync(__dirname + "/static/js/notarize.js", "utf8");
const H = "ab".repeat(32), TX = "0x" + "12".repeat(32), CONTRACT = "0x" + "cd".repeat(20);
const OWNER = "0x" + "ee".repeat(20);

class El {
  constructor() { this.hidden = true; this.className = ""; this.children = []; this._t = ""; this.innerHTML = ""; this.dataset = {}; }
  set textContent(v) { this._t = v; if (v === "") this.children = []; }
  get textContent() { return this._t; }
  appendChild(c) { this.children.push(c); }
  get label() { return this.children[1] ? this.children[1]._t : ""; }
}
class Btn extends El {
  constructor(kind) { super(); this.kind = kind; this.disabled = false; this._t = kind === "n" ? "Notarize" : "Verify"; this.dataset = { docId: "1" }; }
  hasAttribute(a) { return a === (this.kind === "n" ? "data-notarize" : "data-verify"); }
  closest() { return this; }
}

function world(opts = {}) {
  const log = [];
  const result = new El();
  const root = new El(); root.dataset = { contract: CONTRACT, chainId: "80002", rpc: "https://rpc.example", explorer: "https://scan.example", abiUrl: "/abi.json", csrf: "CSRF123" };
  let click; const confirmReplies = (opts.confirm || [[200, { ok: true }]]).slice();
  const fp = opts.fp || { ok: true, current_hash: H, stored_hash: H, status: opts.status || "PENDING", wallet_address: OWNER };

  const doc = {
    readyState: "complete",
    getElementById: (id) => id === "notary-root" ? root : id === "notary-result-1" ? result : null,
    addEventListener: (ev, fn) => { if (ev === "click") click = fn; },
    createElement: () => new El(),
  };
  const reply = (status, data) => ({ status, ok: status < 400, json: async () => data });
  const fetchMock = async (url, init = {}) => {
    log.push(["fetch", url, init.method || "GET", init.headers || null, init.body || null]);
    if (url === "/abi.json") return reply(200, [{ name: "registerDocument" }]);
    if (url.endsWith("/fingerprint")) return reply(200, fp);
    if (url.endsWith("/notarize/confirm")) { const [s, d] = confirmReplies.length > 1 ? confirmReplies.shift() : confirmReplies[0]; return reply(s, d); }
    throw new Error("unexpected fetch " + url);
  };
  let chain = opts.chain || "0x1";
  const ethereum = opts.noWallet ? undefined : {
    request: async ({ method, params }) => {
      log.push(["wallet", method, params]);
      if (opts.walletError && opts.walletError.method === method) throw opts.walletError.err;
      if (method === "eth_chainId") return chain;
      if (method === "wallet_switchEthereumChain") { if (opts.unknownChain) { const e = new Error("Unrecognized chain ID"); e.code = 4902; throw e; } chain = params[0].chainId; return null; }
      return null;
    },
  };
  const ethers = {
    BrowserProvider: class { constructor() { log.push(["BrowserProvider"]); } async getSigner() { return { s: 1 }; } },
    JsonRpcProvider: class { constructor(url, id) { log.push(["JsonRpcProvider", url, id]); } },
    Contract: class {
      constructor(addr, abi, runner) { log.push(["Contract", addr, runner && runner.s ? "signer" : "provider"]); }
      async registerDocument(h, cid) {
        log.push(["registerDocument", h, cid]);
        if (opts.registerError) throw opts.registerError;
        return { hash: TX, wait: async () => (opts.waitReceipt === undefined ? { status: 1 } : opts.waitReceipt) };
      }
      async getRecord(h) { log.push(["getRecord", h]); return opts.record || [true, OWNER, "", 1700000000n]; }
    },
  };
  let reloads = 0;
  const sandbox = {
    document: doc, fetch: fetchMock, Promise, JSON, Number, Date, Error, String, RegExp, TypeError,
    setTimeout: (fn) => { Promise.resolve().then(fn); return 0; },
    window: { ethers: opts.noEthers ? undefined : ethers, ethereum, location: { reload: () => { reloads += 1; } } },
  };
  vm.runInNewContext(SRC, sandbox);
  return {
    log, result, get reloads() { return reloads; },
    async press(kind) {
      const b = new Btn(kind); await click({ target: b });
      // Wait until the async flow has genuinely finished: yield to the event
      // loop (which drains all pending promises) until nothing new happens.
      let last = -1, calm = 0;
      while (calm < 3) {
        await new Promise((r) => setImmediate(r));
        const now = log.length + result.children.length + result._t.length + (result.className || "").length;
        calm = now === last ? calm + 1 : 0; last = now;
      }
      return b;
    },
  };
}

let passed = 0;
async function test(name, fn) { await fn(); passed += 1; console.log("[ OK ] " + name); }
const calls = (w, k) => w.log.filter((l) => l[0] === k);

(async () => {
  await test("Notarize: happy path (switches chain, registers fingerprint only, server confirms, reloads)", async () => {
    const w = world(); const b = await w.press("n");
    const reg = calls(w, "registerDocument");
    assert.strictEqual(reg.length, 1);
    assert.deepStrictEqual(reg[0].slice(1), ["0x" + H, ""], "must send only the fingerprint and an empty cid");
    assert.ok(calls(w, "wallet").some((c) => c[1] === "wallet_switchEthereumChain" && c[2][0].chainId === "0x13882"), "should switch to Amoy (0x13882)");
    assert.deepStrictEqual(calls(w, "Contract")[0].slice(1), [CONTRACT, "signer"]);
    const post = w.log.find((l) => l[0] === "fetch" && l[1].endsWith("/notarize/confirm"));
    assert.strictEqual(post[2], "POST"); assert.strictEqual(post[3]["X-CSRFToken"], "CSRF123");
    assert.deepStrictEqual(JSON.parse(post[4]), { tx_hash: TX }, "server must receive only the tx hash");
    assert.match(w.result.className, /success/); assert.match(w.result.label, /Notarized/);
    assert.strictEqual(w.reloads, 1); assert.strictEqual(b.disabled, true, "stays disabled while the page reloads");
  });
  await test("Notarize: wallet is asked BEFORE anything is sent, and fingerprint is read first", async () => {
    const w = world(); await w.press("n");
    const order = w.log.map((l) => l[0] === "fetch" ? l[1].split("/").pop() : l[0] === "wallet" ? l[1] : l[0]);
    assert.ok(order.indexOf("fingerprint") < order.indexOf("eth_requestAccounts"));
    assert.ok(order.indexOf("eth_requestAccounts") < order.indexOf("registerDocument"));
    assert.ok(order.indexOf("registerDocument") < order.indexOf("confirm"));
  });
  await test("Notarize: already on Amoy -> no chain switch", async () => {
    const w = world({ chain: "0x13882" }); await w.press("n");
    assert.ok(!calls(w, "wallet").some((c) => c[1] === "wallet_switchEthereumChain"));
    assert.strictEqual(calls(w, "registerDocument").length, 1);
  });
  await test("Notarize: wallet doesn't know Amoy yet -> adds it, with the right currency", async () => {
    const w = world({ unknownChain: true }); await w.press("n");
    const add = calls(w, "wallet").find((c) => c[1] === "wallet_addEthereumChain");
    assert.ok(add, "should offer to add the network");
    assert.strictEqual(add[2][0].chainId, "0x13882"); assert.strictEqual(add[2][0].nativeCurrency.symbol, "POL");
  });
  await test("Notarize: user cancels in the wallet -> kind message, button usable again, nothing recorded", async () => {
    const w = world({ walletError: { method: "eth_requestAccounts", err: Object.assign(new Error("denied"), { code: 4001 }) } });
    const b = await w.press("n");
    assert.match(w.result.className, /danger/); assert.match(w.result.label, /cancelled/i);
    assert.strictEqual(b.disabled, false); assert.strictEqual(b.textContent, "Notarize");
    assert.strictEqual(calls(w, "registerDocument").length, 0); assert.strictEqual(w.reloads, 0);
  });
  await test("Notarize: file changed since opt-in -> refuses BEFORE touching the wallet", async () => {
    const w = world({ fp: { ok: true, current_hash: "00".repeat(32), stored_hash: H, status: "PENDING" } });
    await w.press("n");
    assert.match(w.result.label, /changed/i);
    assert.strictEqual(calls(w, "wallet").length, 0); assert.strictEqual(calls(w, "registerDocument").length, 0);
  });
  await test("Notarize: no wallet installed -> tells you to install one", async () => {
    const w = world({ noWallet: true }); await w.press("n");
    assert.match(w.result.label, /MetaMask/); assert.strictEqual(calls(w, "registerDocument").length, 0);
  });
  await test("Notarize: ethers failed to load -> friendly message, no crash", async () => {
    const w = world({ noEthers: true }); const b = await w.press("n");
    assert.match(w.result.label, /library didn't load/i); assert.strictEqual(b.disabled, false);
  });
  await test("Notarize: contract says 'Already registered' -> explained, not a stack trace", async () => {
    const w = world({ registerError: Object.assign(new Error("execution reverted"), { reason: "Already registered", code: "CALL_EXCEPTION" }) });
    await w.press("n"); assert.match(w.result.label, /already recorded/i);
  });
  await test("Notarize: not enough test POL -> points to a faucet", async () => {
    const w = world({ registerError: Object.assign(new Error("x"), { code: "INSUFFICIENT_FUNDS" }) });
    await w.press("n"); assert.match(w.result.label, /faucet/i);
  });
  await test("Notarize: transaction mined but reverted (status 0) -> failure, no confirm sent", async () => {
    const w = world({ waitReceipt: { status: 0 } }); await w.press("n");
    assert.match(w.result.className, /danger/); assert.strictEqual(w.log.filter((l) => l[1] && String(l[1]).endsWith("/confirm")).length, 0);
  });
  await test("Notarize: server says 'pending' twice, then ok -> keeps waiting then succeeds", async () => {
    const w = world({ confirm: [[202, { ok: false, pending: true }], [202, { ok: false, pending: true }], [200, { ok: true }]] });
    await w.press("n");
    assert.strictEqual(w.log.filter((l) => l[1] && String(l[1]).endsWith("/confirm")).length, 3);
    assert.match(w.result.className, /success/);
  });
  await test("Notarize: server never confirms -> gives up with a clear message after 6 tries", async () => {
    const w = world({ confirm: [[202, { ok: false, pending: true }]] }); await w.press("n");
    assert.strictEqual(w.log.filter((l) => l[1] && String(l[1]).endsWith("/confirm")).length, 6);
    assert.match(w.result.label, /longer than usual/i); assert.strictEqual(w.reloads, 0);
  });
  await test("Notarize: server rejects the transaction -> shows the server's reason", async () => {
    const w = world({ confirm: [[400, { ok: false, error: "That transaction doesn't record this document's fingerprint." }]] });
    await w.press("n"); assert.match(w.result.className, /danger/); assert.match(w.result.label, /doesn't record this document/);
  });

  await test("Verify: unchanged file + record on chain -> VERIFIED, read-only (no wallet)", async () => {
    const w = world({ status: "NOTARIZED", noWallet: true }); await w.press("v");
    assert.match(w.result.className, /success/); assert.match(w.result.label, /Verified/); assert.match(w.result.label, /not been changed/);
    assert.strictEqual(calls(w, "BrowserProvider").length, 0, "verify must not need the wallet");
    assert.deepStrictEqual(calls(w, "JsonRpcProvider")[0].slice(1), ["https://rpc.example", 80002]);
    assert.deepStrictEqual(calls(w, "getRecord")[0].slice(1), ["0x" + H]);
  });
  await test("Verify: file changed -> TAMPERED, shown as danger", async () => {
    const w = world({ status: "NOTARIZED", fp: { ok: true, current_hash: "00".repeat(32), stored_hash: H, status: "NOTARIZED", wallet_address: OWNER } });
    await w.press("v"); assert.match(w.result.className, /danger/); assert.match(w.result.label, /Tampered/);
  });
  await test("Verify: no record on chain -> a warning, never 'Verified'", async () => {
    const w = world({ status: "NOTARIZED", record: [false, "0x" + "0".repeat(40), "", 0n] });
    await w.press("v"); assert.match(w.result.className, /warning/); assert.doesNotMatch(w.result.label, /Verified/);
  });
  await test("Verify: record owned by an unexpected wallet -> caution, not 'Verified'", async () => {
    const w = world({ status: "NOTARIZED", record: [true, "0x" + "99".repeat(20), "", 1700000000n] });
    await w.press("v"); assert.match(w.result.className, /warning/); assert.doesNotMatch(w.result.label, /^Verified/);
  });
  await test("Verify: document not notarized -> says so, doesn't query the chain", async () => {
    const w = world({ status: "PENDING" }); await w.press("v");
    assert.match(w.result.label, /hasn't been notarized/i); assert.strictEqual(calls(w, "getRecord").length, 0);
  });
  await test("Verify: button is re-enabled afterwards", async () => {
    const w = world({ status: "NOTARIZED" }); const b = await w.press("v");
    assert.strictEqual(b.disabled, false); assert.strictEqual(b.textContent, "Verify");
  });
  await test("Result text is set as text, never as HTML (no injection via server messages)", async () => {
    const w = world({ confirm: [[400, { ok: false, error: "<img src=x onerror=alert(1)>" }]] }); await w.press("n");
    assert.strictEqual(w.result.label, "<img src=x onerror=alert(1)>");   // present as literal text
    assert.ok(!/onerror/.test(w.result.children[0].innerHTML), "only the constant icon may be innerHTML");
  });

  console.log("\nAll " + passed + " flow checks passed.");
})().catch((e) => { console.error("\n[FAIL]", e.message); process.exit(1); });
