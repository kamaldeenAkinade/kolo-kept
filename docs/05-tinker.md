# Tinker Log — Brute-Force Your Own Login

## What the code actually does (read before predicting)

Two independent defences live in `app/api/auth/login/route.ts`:

| Layer | Constant | Threshold | Window | Response |
|-------|----------|-----------|--------|----------|
| IP rate limiter | `LOGIN_RATE_LIMIT = 5` | 5 requests | 15 min | 429 "Too many login attempts" |
| Account lockout | `LOCKOUT_THRESHOLD = 10` | 10 bad passwords | — | 401 "Invalid email or password" (locked state hidden) |

`checkRateLimit` (`lib/rate-limit.ts:34`) uses `count >= limit`, so it lets the
first 5 requests through and blocks on the 6th.

---

## Pre-run predictions

**Attempt 5**
The rate-limit counter reaches exactly `limit` (5) on this call, but the check
is `count >= limit` evaluated at the *start* of the call — the counter is still
4 when that check runs, so this attempt is allowed. Expected response:
`401 { "error": "Invalid email or password." }`

**Attempt 6**
Now `count = 5 >= 5` at the top of the handler, before any credentials are
checked. Expected response: `429 { "error": "Too many login attempts. Please try again later." }`

**Attempt 11**
Still inside the 15-minute window. The rate-limiter does not reset between
calls; it only resets when `entry.resetAt` expires. Expected response: same 429
as attempt 6 — the account lockout layer (threshold 10) is never reached from
a single IP because the rate limiter stops traffic at attempt 6.

---

## Test script

```bash
#!/usr/bin/env bash
# Usage: bash scripts/brute-login.sh
# Requires the dev server running on localhost:3000

EMAIL="your@email.com"
PASSWORD="wrongpassword"
URL="http://localhost:3000/api/auth/login"

for i in $(seq 1 12); do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
  BODY=$(curl -s -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
  echo "Attempt $i — HTTP $RESPONSE — $BODY"
done
```

Running this (or submitting wrong passwords manually in the browser) produced:

```
Attempt  1 — HTTP 401 — {"error":"Invalid email or password."}
Attempt  2 — HTTP 401 — {"error":"Invalid email or password."}
Attempt  3 — HTTP 401 — {"error":"Invalid email or password."}
Attempt  4 — HTTP 401 — {"error":"Invalid email or password."}
Attempt  5 — HTTP 401 — {"error":"Invalid email or password."}
Attempt  6 — HTTP 429 — {"error":"Too many login attempts. Please try again later."}
Attempt  7 — HTTP 429 — {"error":"Too many login attempts. Please try again later."}
...
Attempt 11 — HTTP 429 — {"error":"Too many login attempts. Please try again later."}
Attempt 12 — HTTP 429 — {"error":"Too many login attempts. Please try again later."}
```

---

## Prediction vs reality

| | Attempt 5 | Attempt 6 | Attempt 11 |
|---|---|---|---|
| **Predicted** | 401 Invalid credentials | 429 Too many attempts | 429 Too many attempts |
| **Observed** | 401 Invalid credentials | 429 Too many attempts | 429 Too many attempts |
| **Match?** | ✓ | ✓ | ✓ |

**The initial gut prediction** ("prevent login after the 5th") was correct about
the cutoff point, but incomplete in two ways:

1. **Two layers, not one.** The gut model assumed a single lockout. The code has
   an IP-level rate limiter (trips at attempt 6) *and* a per-account lockout
   (trips at 10 bad passwords). A single IP can never reach the account-lockout
   layer on its own because the rate limiter stops it first.

2. **The message changes.** Attempts 1–5 return `401` with a credentials error.
   Attempt 6 returns `429` with a different message and a `Retry-After` header.
   The prediction didn't account for the distinct HTTP status or the second error
   string — that distinction matters when writing a client that needs to show the
   user the right UI.

3. **Lockout at 10 is reachable — just not from one IP.** An attacker using
   distributed IPs (one request per IP) bypasses the rate limiter entirely and
   can accumulate `failedAttempts` toward the 10-attempt account lockout. The two
   defences cover different threat models and neither alone is sufficient.
