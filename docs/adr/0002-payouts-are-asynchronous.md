# ADR 0002: payouts are asynchronous

**Status:** accepted, from spike S3 (real sandbox, 2026-10-21)

`CreatePayout` returned batch status `PROCESSING` and the item `PENDING`, and
was still not final after about 10 seconds of polling. PAID_OUT therefore means
"payout submitted to PayPal", not "money arrived". The batch status is recorded in
the ledger event.

**Still to do:** poll `GetPayout` (or use the PAYMENT.PAYOUTS-ITEM.* webhook) and
record the final status; surface UNCLAIMED/FAILED/RETURNED items in the dashboard.

# ADR 0003: authorization honor window

Spike S1 showed authorizations valid for about 29 days in the sandbox. PayPal's
documented guaranteed honor period is shorter (about 3 days), so Leash keeps its
delivery deadline (R9) at 3 days or less and captures early. Voiding the remainder
after a partial capture works; a void of a whole authorization leaves the buyer uncharged.