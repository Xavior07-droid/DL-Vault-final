# Blockchain setup — Step 22 (wallet & network)

This part is **optional**. The whole vault works without it. It only matters if
you want to use the document notarization feature added in Phase E.

Steps 1–3 below have to be done by **you**, in your own browser — they involve a
recovery phrase that only you should ever see. When you're done, a small script
checks that everything is wired up correctly.

> **The one rule.** Your wallet's **seed phrase** (12 or 24 words) and any
> **private key** are the keys to everything in that wallet. They never go in
> this project, in `.env`, in a chat, in a screenshot, or in a commit. Nothing
> in this app ever asks for them. Only your **public address** (starts with
> `0x`) is safe to share.

---

## 1. Create a wallet (MetaMask)

1. Install the MetaMask extension **only from the official site,
   [metamask.io](https://metamask.io)** — fake copies exist.
2. Choose **Create a new wallet** and set a password.
3. MetaMask shows a **Secret Recovery Phrase**. Write it on paper and keep it
   somewhere safe and offline. Anyone who has it controls the wallet, and if you
   lose it, it cannot be recovered.

**Use a fresh wallet just for this project.** Don't reuse a wallet that holds
real money. This one only ever needs free test tokens.

## 2. Add the Polygon Amoy test network

In MetaMask: network dropdown → **Add a custom network** (or Settings →
Networks → Add), then enter:

| Field | Value |
|---|---|
| Network name | `Polygon Amoy` |
| RPC URL | `https://rpc-amoy.polygon.technology` |
| Chain ID | `80002` |
| Currency symbol | `POL` |
| Block explorer | `https://amoy.polygonscan.com` |

Save, then switch MetaMask to this network. Double-check the chain ID says
`80002` — Polygon **mainnet** is `137`, and that one uses real money.

> **A note on names:** older guides say the test token is "MATIC". Polygon has
> renamed it to **POL**, so that is what you'll see in MetaMask and the faucets.
> Same thing, new name.

> **If the RPC is flaky:** public RPC endpoints are shared and are sometimes slow
> or rate-limited. That's normal. You can swap in another Amoy RPC URL in
> MetaMask and in `.env` — the chain ID stays `80002`.

## 3. Get free test POL from a faucet

Test POL has no real value; it just pays the tiny fee for a test transaction.

1. In MetaMask, click your account name to **copy your public address**.
2. Use an Amoy faucet, for example the official one at
   [faucet.polygon.technology](https://faucet.polygon.technology), or the
   Alchemy / QuickNode / OnFinality faucets. Select **Polygon Amoy**, paste your
   address, and submit.
3. Wait a minute or so, then check that your MetaMask balance is above 0.

If a request fails, the usual causes are: a cooldown (faucets typically allow one
request per wallet every 12–24 hours), a failed bot check, having the wrong
network selected, or the faucet itself running low. Trying a different faucet
usually fixes it.

## 4. Tell the project your public address

```bash
cp .env.example .env      # skip if you already have a .env
```

Open `.env` and set **only** these:

```
NOTARIZATION_WALLET_ADDRESS=0xYourPublicAddressHere
POLYGON_AMOY_RPC_URL=https://rpc-amoy.polygon.technology
```

(You can leave `POLYGON_AMOY_RPC_URL` blank to use that default.)

## 5. Check it worked

```bash
python check_wallet_setup.py            # offline: checks the format of what you entered
python check_wallet_setup.py --online   # also confirms the network and your balance
```

What the check looks for:

- ✅ No private key or seed phrase has been pasted into `.env` (it stops
  immediately if it finds one, and never prints it back)
- ✅ Your address is well-formed
- ✅ The RPC is reachable and is genuinely **Amoy (chain id 80002)** — it fails
  loudly if you accidentally point at mainnet
- ✅ Your wallet has test POL

It only reads public information and needs no extra packages.

---

**Done when** `check_wallet_setup.py --online` reports `all checks passed`.
Next is Step 23: writing and deploying the notarization smart contract in Remix.
