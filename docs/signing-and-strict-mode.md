# Running Leash for real: signing, strict mode and the taint window

This is what changes when you run `leash serve` against a real PayPal sandbox
instead of the seeded fake demo.

## What strict mode means

`leash serve` runs **strict** unless you are in the seeded fake demo (`-fake` with
the default `-seed`), where the demo user's key lives inside the process.

- Approvals need **your signature**. The operator token alone cannot approve a
  payment: a stolen token can look, but it cannot spend.
- The first user key is enrolled through the API with the operator token as the
  enrollment secret, so a stranger who reaches a new server cannot pin their own key.
- Agent sessions are issued by the server. An agent cannot pick or switch its own.

## The signing key

Open the dashboard and look at **Your signing key**.

1. **Create my signing key.** The browser makes a P-256 key pair. The private key is
   stored in IndexedDB as a *non-extractable* key: the page can ask the browser to
   sign with it, but nothing can read it out. Leash pins the public key.
2. **New mandate** builds the mandate text from the form, signs exactly that text,
   and sends both. Leash checks the signature over the bytes it received, then
   parses them strictly.
3. **Approve** on a step-up asks the server for the approval text
   (`leash.approve.v1`, request id, merchant, amount), shows you the amount and
   merchant, and signs it only after you confirm.

Needs a secure page: `https://`, or `http://localhost`.

**Losing the key.** A non-extractable key cannot be backed up. If you clear the
browser's site data you lose the ability to sign, and the server will keep trusting
the old key. For now the only recovery is a fresh data directory (`-data`). Key
rotation is a good next feature; until then, treat the browser profile that holds
the key like a hardware token.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `-strict` | `true` | Signed approvals, issued sessions, enrollment secret. Off only in the seeded fake demo. |
| `-taint-window` | `10m` | After a page with planted instructions is read, every payment needs your approval for this long, from any session. `0` turns it off. |
| `-public-url` | `$LEASH_PUBLIC_URL` | Public https address. Buyers who approve in PayPal land back on `/paypal/return`. |
| `-approval-ttl` | `3h` | How long an approved payment may wait for the buyer to approve in PayPal. |
| `-inspection` | `0` | Keep a delivered purchase on hold this long before paying the merchant, so you can still object. |

On a hosting platform (`PORT` set) the tokens must come from `LEASH_ADMIN_TOKEN` and
`LEASH_AGENT_TOKEN`; Leash refuses to invent them, because a generated token would
end up in the platform's logs. Use at least 32 random characters
(`openssl rand -hex 24`).

## The taint window

Starting a new MCP session used to give an agent a clean slate: a poisoned page read
in one session was forgotten by the next. With the taint window on, a serious
injection attempt makes **every** payment wait for you until the window ends. It
survives a restart. The offline demo turns it off so its scripted attack does not
slow down your first live purchase.

## Signed quotes

A merchant's quote is what Leash trusts for a price, so it is fetched over https
(plain http only for localhost), redirects are refused, and the quote must be for the
merchant and id asked for. For extra protection, give the merchant a `quote_secret`
in `merchants.json`. Leash then refuses any quote that does not carry

    X-Leash-Signature: base64( HMAC-SHA256( quote_secret, response body ) )

so nobody on the path can change the price. In Go: `control.SignQuote(secret, body)`.

## Merchants file

Copy `merchants.example.json` to `merchants.json` (it is git-ignored) and replace
every value that starts with `REPLACE`. Leash refuses to start with placeholders.

## How a merchant confirms delivery

Funds stay in escrow until the merchant says the purchase was delivered. The merchant
has its own door, separate from the operator API and from the agent's MCP endpoint:

    POST /merchant/delivery
    Authorization: Bearer <the merchant's delivery_secret>
    {"merchant_id":"legitgifts","request_id":"req_...","delivered":true,"reference":"TRK-1"}

`delivered: true` captures the held funds and pays the merchant. `delivered: false`
releases the hold, so the buyer is never charged. Every authentication failure gets the
same answer (403), so the endpoint does not say which part was wrong, and ten wrong
secrets in a minute for one merchant id are answered with 429. The merchant's secret
opens nothing else, and the operator token is not accepted here.

## Pending captures and payouts need no webhooks

`Plane.Sweep` runs at startup and every 30 seconds. It polls PayPal for captures and
payouts that are still pending, retries steps that failed, and expires requests that
waited too long. No public webhook URL is required.

## Checking it all works

    go test ./...                             # Go tests, plus the signing script's Node tests
    cd web/e2e && npm install && node dashboard.e2e.mjs   # the real dashboard, in jsdom, against a real server
