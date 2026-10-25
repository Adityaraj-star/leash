# PayPal spikes (Gate G1)

Results of `go run ./cmd/spike`. Decisions go in docs/adr/.

## Run 2026-10-21T18:31:31Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S1 | create AUTHORIZE order | PASS |  |
| S1 | order status | PASS | status=PAYER_ACTION_REQUIRED approve_link=true |
| S1 | buyer approval | PASS |  |
| S1 | authorize | PASS |  |
| S1 | authorization | PASS | id=1S4225165W210321W status=CREATED expires=2026-11-19T18:29:36Z (created 2026-10-21T18:29:36Z): record this honor window in the ADR |
| S1 | partial capture $2.00 of $5.00 | PASS |  |
| S1 | capture | PASS | id=4VH17532UJ931761X status=COMPLETED final=false |
| S1 | void remainder after a partial capture | PASS |  |
| S1 | authorization status afterwards | PASS | VOIDED |
| S1 | second order | PASS |  |
| S1 | second buyer approval | PASS |  |
| S1 | second authorize | PASS |  |
| S1 | void the whole authorization | PASS |  |
| S1 | status is VOIDED (buyer never charged) | PASS | status=VOIDED |

## Run 2026-10-21T18:36:41Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S3 | create payout | PASS |  |
| S3 | payout batch | PASS | batch=XUSUVKEC68DM8 status=PROCESSING items=1 |
| S3 | item status | PASS | PENDING |
| S3 | webhooks | PASS | run `spike s3-webhook -webhook-id ID` behind cloudflared/ngrok, register that URL for PAYMENT.CAPTURE.* and PAYMENT.PAYOUTS-ITEM.* events, then trigger the flows above. Fallback if tunnels fail: poll order and payout status. |

## Run 2026-10-21T18:57:20Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S3 | create payout | PASS |  |
| S3 | payout batch | PASS | batch=SH6BCWWLEREWU status=PROCESSING items=1 |
| S3 | payout item not denied | PASS | item status=SUCCESS |
| S3 | webhooks | PASS | run `spike s3-webhook -webhook-id ID` behind cloudflared/ngrok, register that URL for PAYMENT.CAPTURE.* and PAYMENT.PAYOUTS-ITEM.* events, then trigger the flows above. Fallback if tunnels fail: poll order and payout status. |

## Run 2026-10-25T18:14:28Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S1 | create AUTHORIZE order | PASS |  |
| S1 | order status | PASS | status=PAYER_ACTION_REQUIRED approve_link=true |
| S1 | buyer approval | PASS |  |
| S1 | authorize | PASS |  |
| S1 | authorization | PASS | id=7X3206208P1355633 status=CREATED expires=2026-11-23T18:13:43Z (created 2026-10-25T18:13:43Z): record this honor window in the ADR |
| S1 | partial capture $2.00 of $5.00 | PASS |  |
| S1 | capture | PASS | id=96412270DU9665923 status=COMPLETED final=false |
| S1 | void remainder after a partial capture | PASS |  |
| S1 | authorization status afterwards | PASS | VOIDED |
| S1 | second order | PASS |  |
| S1 | second buyer approval | PASS |  |
| S1 | second authorize | PASS |  |
| S1 | void the whole authorization | PASS |  |
| S1 | status is VOIDED (buyer never charged) | PASS | status=VOIDED |

## Run 2026-10-25T18:16:35Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S3 | create payout | FAIL | HTTP 400 VALIDATION_ERROR: Invalid request - see details (debug id f58794047e28f) |

## Run 2026-10-25T18:20:17Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S3 | create payout | PASS |  |
| S3 | payout batch | PASS | batch=XTNL5TY5WVHW4 status=SUCCESS items=1 |
| S3 | payout item not denied | PASS | item status=SUCCESS |
| S3 | webhooks | PASS | run `spike s3-webhook -webhook-id ID` behind cloudflared/ngrok, register that URL for PAYMENT.CAPTURE.* and PAYMENT.PAYOUTS-ITEM.* events, then trigger the flows above. Fallback if tunnels fail: poll order and payout status. |

## Run 2026-10-25T19:14:11Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S1 | create AUTHORIZE order | PASS |  |
| S1 | order status | PASS | status=PAYER_ACTION_REQUIRED approve_link=true |
| S1 | buyer approval | PASS |  |
| S1 | authorize | PASS |  |
| S1 | authorization | PASS | id=2DG02751UU814512Y status=CREATED expires=2026-11-23T19:13:29Z (created 2026-10-25T19:13:29Z): record this honor window in the ADR |
| S1 | partial capture $2.00 of $5.00 | PASS |  |
| S1 | capture | PASS | id=7MB4835760274982V status=COMPLETED final=false |
| S1 | void remainder after a partial capture | PASS |  |
| S1 | authorization status afterwards | PASS | VOIDED |
| S1 | second order | PASS |  |
| S1 | second buyer approval | PASS |  |
| S1 | second authorize | PASS |  |
| S1 | void the whole authorization | PASS |  |
| S1 | status is VOIDED (buyer never charged) | PASS | status=VOIDED |

## Run 2026-10-25T19:15:05Z (sandbox)

| Spike | Check | Result | Detail |
|---|---|---|---|
| S3 | create payout | PASS |  |
| S3 | payout batch | PASS | batch=UUNG8YA6SYF7N status=SUCCESS items=1 |
| S3 | payout item not denied | PASS | item status=SUCCESS |
| S3 | webhooks | PASS | run `spike s3-webhook -webhook-id ID` behind cloudflared/ngrok, register that URL for PAYMENT.CAPTURE.* and PAYMENT.PAYOUTS-ITEM.* events, then trigger the flows above. Fallback if tunnels fail: poll order and payout status. |
