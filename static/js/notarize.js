/*
 * notarize.js — Steps 25–26
 *
 * Browser side of document notarization on the Documents page.
 *
 *   Notarize  fingerprint -> your wallet signs ONE small transaction ->
 *             the server checks the transaction on the blockchain itself ->
 *             the document is marked Notarized.
 *   Verify    re-fingerprints the stored file, reads the blockchain record
 *             (read-only, no wallet needed) and compares the two.
 *
 * Only the SHA-256 fingerprint is ever sent to the blockchain. The file, its
 * name and any personal data never leave the vault. No private key or seed
 * phrase is ever seen or needed here — the wallet does the signing.
 *
 * Layout: the first half is plain logic (unit-tested with node, see
 * check_notarize_js.js). The second half wires it to the page.
 */
(function () {
  "use strict";

  // ------------------------------------------------------------------
  // Plain logic
  // ------------------------------------------------------------------

  /** An error whose message is already safe and friendly to show as-is. */
  function friendly(message) {
    var err = new Error(message);
    err.friendly = true;
    return err;
  }

  /** "ab…" (64 hex chars, no prefix) -> "0xab…" lowercase, for the contract. */
  function toBytes32(hex) {
    if (typeof hex !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(hex)) {
      throw friendly("That fingerprint isn't valid.");
    }
    return "0x" + hex.replace(/^0x/, "").toLowerCase();
  }

  /** "0x1234…cdef" for display. */
  function shortAddress(address) {
    if (typeof address !== "string" || address.length < 12) { return address || ""; }
    return address.slice(0, 6) + "…" + address.slice(-4);
  }

  /**
   * Compare what is on the blockchain with the file as it is now.
   *
   *   storedHash   fingerprint saved when the document was notarized
   *   currentHash  fingerprint of the stored file, computed just now
   *   record       { exists, owner, timestamp } read from the contract
   *   expectedOwner  optional wallet we expect to have registered it
   *
   * Returns { state }, state being VERIFIED | TAMPERED | MISSING | OWNER_MISMATCH
   */
  function decideVerification(storedHash, currentHash, record, expectedOwner) {
    if (!record || !record.exists) { return { state: "MISSING" }; }
    if (expectedOwner && record.owner &&
        expectedOwner.toLowerCase() !== record.owner.toLowerCase()) {
      return { state: "OWNER_MISMATCH" };
    }
    var same = String(storedHash).toLowerCase() === String(currentHash).toLowerCase();
    return { state: same ? "VERIFIED" : "TAMPERED" };
  }

  /**
   * The badge to show on a document after a Verify, for a decideVerification
   * state. Only VERIFIED ever says "Verified"; anything we couldn't confirm is
   * a caution, never a pass. icon names a key of ICONS (page wiring below).
   */
  function badgeFor(state) {
    if (state === "VERIFIED") { return { kind: "pass", icon: "success", label: "Verified" }; }
    if (state === "TAMPERED") { return { kind: "danger", icon: "danger", label: "Tampered" }; }
    return { kind: "warning", icon: "warning", label: "Couldn\u2019t confirm" };
  }

  /** Turn any error from the wallet, the network or us into a kind sentence. */
  function explainError(err) {
    if (err && err.friendly) { return err.message; }
    var text = String((err && (err.reason || err.shortMessage || err.message)) || err || "");
    var code = err && err.code;
    if (code === 4001 || code === "ACTION_REJECTED" || /user (rejected|denied)/i.test(text)) {
      return "You cancelled the request in your wallet, so nothing was recorded.";
    }
    if (/already registered/i.test(text)) {
      return "This exact file is already recorded on the blockchain (possibly by an " +
             "earlier attempt), so it can't be registered a second time.";
    }
    if (code === "INSUFFICIENT_FUNDS" || /insufficient funds/i.test(text)) {
      return "Your wallet doesn't have enough test POL to pay the small network fee. " +
             "Get some from a faucet, then try again.";
    }
    if (code === "NETWORK_ERROR" || code === "SERVER_ERROR" || code === "TIMEOUT" ||
        /failed to fetch|network error|timeout/i.test(text)) {
      return "Couldn't reach the blockchain. Check your connection and try again.";
    }
    return "Something went wrong: " + text.slice(0, 180);
  }

  var api = {
    friendly: friendly,
    toBytes32: toBytes32,
    shortAddress: shortAddress,
    decideVerification: decideVerification,
    badgeFor: badgeFor,
    explainError: explainError
  };

  // Under node (tests) just export the logic; in a browser, wire up the page.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
    return;
  }

  // ------------------------------------------------------------------
  // Page wiring (browser only)
  // ------------------------------------------------------------------

  var ICONS = {
    info:    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>',
    success: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>',
    danger:  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
    warning: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
  };

  function init() {
    var rootEl = document.getElementById("notary-root");
    if (!rootEl) { return; }

    var cfg = {
      contract: rootEl.dataset.contract,
      chainId: Number(rootEl.dataset.chainId),
      rpc: rootEl.dataset.rpc,
      explorer: rootEl.dataset.explorer,
      abiUrl: rootEl.dataset.abiUrl,
      csrf: rootEl.dataset.csrf
    };

    var abiPromise = null;
    function loadAbi() {
      if (!abiPromise) {
        abiPromise = fetch(cfg.abiUrl, { credentials: "same-origin" }).then(function (r) {
          if (!r.ok) { throw friendly("Couldn't load the notarization settings. Refresh the page and try again."); }
          return r.json();
        });
      }
      return abiPromise;
    }

    function sleep(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }

    function show(docId, kind, text) {
      var el = document.getElementById("notary-result-" + docId);
      if (!el) { return; }
      el.hidden = false;
      el.className = "notary-result notary-result-" + kind;
      el.textContent = "";
      var icon = document.createElement("span");
      icon.className = "notary-result-icon";
      icon.innerHTML = ICONS[kind] || ICONS.info;       // constant markup only
      var label = document.createElement("span");
      label.textContent = text;                         // never innerHTML
      el.appendChild(icon);
      el.appendChild(label);
    }

    // Swap the status badge beside a document to reflect a fresh Verify.
    // Constant icon markup + textContent only; a missing element is ignored.
    function setBadge(docId, state) {
      var el = document.getElementById("notary-badge-" + docId);
      if (!el) { return; }
      var b = badgeFor(state);
      var badge = document.createElement("span");
      badge.className = "badge badge-" + b.kind;
      var icon = document.createElement("span");
      icon.innerHTML = ICONS[b.icon] || ICONS.info;      // constant markup only
      var label = document.createElement("span");
      label.textContent = b.label;
      badge.appendChild(icon);
      badge.appendChild(label);
      el.textContent = "";
      el.appendChild(badge);
    }

    function busy(btn, on, workingText) {
      if (on) {
        btn.dataset.label = btn.textContent;
        btn.textContent = workingText || "Working…";
        btn.disabled = true;
      } else {
        btn.textContent = btn.dataset.label || btn.textContent;
        btn.disabled = false;
      }
    }

    function parse(response) {
      return response.json().then(function (data) {
        return { status: response.status, data: data };
      }, function () {
        throw friendly("Couldn't read the server's reply. Refresh the page and try again.");
      });
    }

    function getFingerprint(docId) {
      return fetch("/documents/" + docId + "/fingerprint", { credentials: "same-origin" })
        .then(parse).then(function (r) {
          if (!r.data || r.data.ok === false) {
            throw friendly((r.data && r.data.error) || "Couldn't read this document's fingerprint.");
          }
          return r.data;
        });
    }

    function postConfirm(docId, txHash) {
      return fetch("/documents/" + docId + "/notarize/confirm", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRFToken": cfg.csrf },
        body: JSON.stringify({ tx_hash: txHash })
      }).then(parse);
    }

    // Ask the server to check the transaction; wait if the chain is still mining it.
    function confirmOnServer(docId, txHash) {
      var attempt = 0;
      function once() {
        attempt += 1;
        return postConfirm(docId, txHash).then(function (r) {
          if (r.status === 202 || (r.data && r.data.pending)) {
            if (attempt >= 6) {
              throw friendly("The blockchain is taking longer than usual to confirm. " +
                "Refresh this page in a minute to see the result.");
            }
            return sleep(3000).then(once);
          }
          if (r.data && r.data.ok) { return r.data; }
          throw friendly((r.data && r.data.error) || "Couldn't save the result.");
        });
      }
      return once();
    }

    function ensureAmoy() {
      var hex = "0x" + cfg.chainId.toString(16);
      return window.ethereum.request({ method: "eth_chainId" }).then(function (current) {
        if (String(current).toLowerCase() === hex) { return; }
        return window.ethereum.request({
          method: "wallet_switchEthereumChain", params: [{ chainId: hex }]
        }).catch(function (e) {
          if (e && (e.code === 4902 || /unrecognized chain/i.test(String(e.message)))) {
            return window.ethereum.request({
              method: "wallet_addEthereumChain",
              params: [{
                chainId: hex,
                chainName: "Polygon Amoy",
                nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 },
                rpcUrls: [cfg.rpc],
                blockExplorerUrls: [cfg.explorer]
              }]
            });
          }
          throw e;
        });
      });
    }

    // ---- Notarize ---------------------------------------------------
    async function notarize(btn) {
      var docId = btn.dataset.docId;
      busy(btn, true, "Working…");
      try {
        if (!window.ethers) { throw friendly("The notarization library didn't load. Refresh the page and try again."); }
        if (!window.ethereum) {
          throw friendly("No wallet found. Install the MetaMask browser extension, then try again.");
        }

        show(docId, "info", "Checking your file…");
        var fp = await getFingerprint(docId);
        if (!fp.stored_hash) { throw friendly("This document wasn't set up for notarization."); }
        if (fp.current_hash !== fp.stored_hash) {
          throw friendly("This file has changed since its fingerprint was saved, so it can't be notarized.");
        }
        var hash = toBytes32(fp.stored_hash);

        show(docId, "info", "Connecting to your wallet…");
        await window.ethereum.request({ method: "eth_requestAccounts" });
        await ensureAmoy();

        var abi = await loadAbi();
        var provider = new window.ethers.BrowserProvider(window.ethereum);
        var signer = await provider.getSigner();
        var contract = new window.ethers.Contract(cfg.contract, abi, signer);

        show(docId, "info", "Please confirm the transaction in your wallet. Only the fingerprint is recorded.");
        // Second argument is the optional IPFS id; empty = fingerprint only.
        var tx = await contract.registerDocument(hash, "");

        show(docId, "info", "Recording on the blockchain… this usually takes a few seconds.");
        var receipt = await tx.wait();
        if (receipt && receipt.status === 0) { throw friendly("The transaction failed on the blockchain."); }

        show(docId, "info", "Saving the result…");
        await confirmOnServer(docId, tx.hash);

        show(docId, "success", "Notarized. The fingerprint is now recorded on the blockchain.");
        setTimeout(function () { window.location.reload(); }, 1600);
      } catch (err) {
        show(docId, "danger", explainError(err));
        busy(btn, false);
      }
    }

    // ---- Verify -----------------------------------------------------
    async function verify(btn) {
      var docId = btn.dataset.docId;
      busy(btn, true, "Checking…");
      try {
        if (!window.ethers) { throw friendly("The notarization library didn't load. Refresh the page and try again."); }
        show(docId, "info", "Re-reading your file and checking the blockchain…");
        var fp = await getFingerprint(docId);
        if (fp.status !== "NOTARIZED" || !fp.stored_hash) {
          throw friendly("This document hasn't been notarized yet.");
        }

        var abi = await loadAbi();
        // Read-only: a plain RPC connection, so no wallet is needed to verify.
        var provider = new window.ethers.JsonRpcProvider(cfg.rpc, cfg.chainId);
        var contract = new window.ethers.Contract(cfg.contract, abi, provider);
        var r = await contract.getRecord(toBytes32(fp.stored_hash));

        var record = { exists: r[0], owner: r[1], timestamp: Number(r[3]) };
        var decision = decideVerification(fp.stored_hash, fp.current_hash, record, fp.wallet_address);
        var when = record.exists
          ? new Date(record.timestamp * 1000).toLocaleDateString(undefined,
              { year: "numeric", month: "long", day: "numeric" })
          : "";

        setBadge(docId, decision.state);
        if (decision.state === "VERIFIED") {
          show(docId, "success", "Verified. This file is exactly the one notarized on " + when +
               " by wallet " + shortAddress(record.owner) + ". It has not been changed.");
        } else if (decision.state === "TAMPERED") {
          show(docId, "danger", "Tampered. This file is different from the one notarized on " +
               when + ". It has been changed since.");
        } else if (decision.state === "OWNER_MISMATCH") {
          show(docId, "warning", "The blockchain record exists but was registered by a different " +
               "wallet than expected. Treat this result with caution.");
        } else {
          show(docId, "warning", "Couldn't find this document's record on the blockchain. " +
               "It may still be confirming, or the contract address may have changed.");
        }
      } catch (err) {
        show(docId, "danger", explainError(err));
      } finally {
        busy(btn, false);
      }
    }

    document.addEventListener("click", function (event) {
      var btn = event.target.closest("[data-notarize], [data-verify]");
      if (!btn || btn.disabled) { return; }
      if (btn.hasAttribute("data-notarize")) { notarize(btn); } else { verify(btn); }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
