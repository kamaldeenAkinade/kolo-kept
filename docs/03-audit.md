# Security Audit — Kolo Kept Auth Layer

This document audits the authentication system against six specific threat areas. Every
finding is labelled with a severity (Critical / Medium / Low / Informational), explains
what the attack is in plain language, shows exactly which lines are involved, and
describes what a fix would look like. Findings do not mean the code is bad — they are
the gap between what the code does and what a hardened production system would require.

---

## How to Read Severity Labels

- **Critical** — An attacker can realistically extract useful information or take a
  harmful action with low effort. Fix before shipping.
- **Medium** — The attack is real but requires more effort, specific conditions, or only
  partially succeeds. Fix before a security review.
- **Low** — A real weakness, but hard to exploit or limited in damage. Fix when
  convenient or when the system matures.
- **Informational** — A design note worth understanding, not an active risk.

---

## Area 1 — Enumeration Attacks Through Response Timing

An "enumeration attack" means an attacker uses your system to learn whether a specific
email address is registered, without you intending to tell them. The generic error
message approach (showing the same text for "email exists" and "email doesn't exist")
is the right instinct. But if the code takes different amounts of time to respond
depending on the answer, the timing itself becomes the oracle — even if the words are
identical.

Think of it like this: if a bouncer says "not on the list" to everyone but waves some
people through in 1 second and makes others wait 5 minutes, you can guess who's on the
list just by watching how long each person stands at the door.

---

### Finding 1.1 — Signup Response Time Leaks Whether an Email Is Registered

**Severity: Critical**

**File:** `app/api/auth/signup/route.ts`

**What happens:**

When an email is already registered, the signup handler hits the database, finds the
user, and immediately returns a 409 response — no hashing involved. The whole thing
takes a few milliseconds.

```
Line 33–36: DB lookup (fast — finds a user, returns quickly)
Line 38–44: Return 409 immediately — no bcrypt is ever run
```

When an email is NOT registered, the handler validates the password strength, looks up
the database (finds nothing), then runs:

```
Line 46: const passwordHash = await bcrypt.hash(password, 12);
```

bcrypt at cost 12 deliberately takes 200–400 milliseconds. That is the entire point —
slow hashing resists offline brute-force attacks. But it also means an existing email
gets a response in ~5ms, and a new email gets a response in ~300ms.

An attacker feeds in a list of email addresses, measures response times, and separates
"already registered" from "not registered" with high confidence. The error message
("Unable to create account. Please try a different email.") is generic and gives nothing
away — but the timing tells the whole story.

**The fix:**

When the email already exists, still run a bcrypt hash on a dummy value before
returning. This wastes ~300ms on purpose and makes both paths take the same time.

```typescript
if (existing) {
  await bcrypt.hash("dummy-equalize-timing", 12); // timing equalization
  return NextResponse.json(
    { error: "Unable to create account. Please try a different email." },
    { status: 409 }
  );
}
```

The login handler (`app/api/auth/login/route.ts:44–51`) already does this correctly
with its dummy hash — the same pattern needs to be applied here.

---

### Finding 1.2 — Password Reset Request Timing Leaks Whether an Email Is Registered

**Severity: Critical**

**File:** `app/api/auth/reset-password/request/route.ts`

**What happens:**

When the submitted email is NOT registered, the handler does one database read and
returns the generic response. Fast: ~5ms.

When the submitted email IS registered, the handler:
1. Reads the database (finds the user)
2. Runs `updateMany` to invalidate old tokens (database write)
3. Generates a UUID token
4. Runs `await bcrypt.hash(rawToken, 10)` — line 54 — slow: ~65ms at cost 10
5. Writes a new record to the database
6. Logs or emails the token
7. Returns the generic response

Even though both paths return the same body and the same HTTP status code, the response
time for a registered email is 100–200ms longer than for an unregistered one. An
attacker can enumerate registered emails by watching how long the server takes to
respond to reset requests for each email they test.

Note that even the rate-limiting path (lines 26–27) returns immediately for any IP that
has hit the limit — but the rate limit operates per IP, not per email, so an attacker
rotating through different IPs can still probe many emails before being throttled.

**The fix:**

When the email is not found, still run a fake bcrypt hash and a fake database write (or
just the hash) to equalize timing before returning:

```typescript
if (!user) {
  await bcrypt.hash("dummy-equalize-timing", 10); // match real path timing
  return NextResponse.json(GENERIC_RESPONSE);
}
```

---

### Finding 1.3 — Login Path Timing Difference When Wrong Password vs. Missing User

**Severity: Low**

**File:** `app/api/auth/login/route.ts`

**What happens:**

The login handler does run a dummy bcrypt comparison when the user doesn't exist
(lines 44–51) — that is the right move, and it equalizes the main timing difference.
However, there is a secondary timing gap.

When the user EXISTS and the password is wrong (lines 67–82), the handler runs a
database write to increment `failedAttempts`:

```
Line 71–79: prisma.user.update({ data: { failedAttempts: newFailedAttempts, ... } })
```

When the user does NOT exist, no such write happens — the handler just does the dummy
bcrypt and returns. Database writes typically add 10–50ms of latency. Under careful
measurement in a low-noise environment, this difference is detectable.

There is also a subtler gap from the lockout path (lines 55–63): a locked account
returns BEFORE running bcrypt.compare, skipping ~100ms of hashing. A 423 response time
is significantly shorter than a 401 for a wrong password, which reveals that the account
exists AND is locked.

**The fix:**

The lockout check is the more exploitable gap. Consider moving the lockout check to
AFTER the bcrypt comparison, or still running bcrypt.compare even for locked accounts
and returning the same INVALID_CREDENTIALS timing profile regardless. The failedAttempts
write timing gap is harder to exploit and lower priority.

---

## Area 2 — CSRF Gaps on the Password Reset Endpoint

CSRF (Cross-Site Request Forgery) means a malicious website tricks your browser into
making a request to a different website — your app — using your existing cookies or
session. The defence in this codebase is the double-submit pattern: a CSRF token stored
in a readable cookie and required in a request header. State-changing routes all call
`validateCsrf` before doing anything.

But what about routes that have no session? You can't double-submit a CSRF token you
don't have yet.

---

### Finding 2.1 — Reset Request Endpoint Has No CSRF Protection and Can Be Abused for Email Flooding

**Severity: Medium**

**File:** `app/api/auth/reset-password/request/route.ts`

**What happens:**

The reset request endpoint is public — it intentionally requires no session. This means
the double-submit CSRF pattern cannot be applied. But the lack of CSRF protection creates
a different problem.

A malicious page on any domain can send a JSON POST to your reset endpoint with a
victim's email address:

```javascript
// malicious page on attacker.com
fetch("https://yourdomain.com/api/auth/reset-password/request", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "victim@example.com" })
});
```

The browser will not block this request from being sent (CORS only blocks the browser
from reading the response, not from sending the request). The server receives and
processes it. If the email is registered, a reset token is created and an email is
dispatched.

The practical consequence: an attacker can trigger unsolicited password reset emails for
any user, repeatedly, from any page that the victim visits or that runs in an automated
script. With the rate limit at 3 per IP per hour, and IPs being easy to rotate, this
can be used for sustained email harassment.

A secondary consequence: every time this is triggered, the previous reset token is
invalidated (lines 47–50). If a legitimate user requested a reset, an attacker can race
them and invalidate their token before they use it.

**The fix:**

There is no perfect solution for public endpoints, but several partial mitigations:
- Require a human-verification step (CAPTCHA or proof-of-work) before sending reset emails
- Limit resets per email address (not just per IP) — currently only IP is rate-limited
- For the token invalidation race: consider not invalidating existing tokens immediately,
  only marking them superseded, or adding a short grace period

---

### Finding 2.2 — Reset Confirm Has No CSRF — By Design, and It Is Acceptable

**Severity: Informational**

**File:** `app/api/auth/reset-password/confirm/route.ts`

The confirm endpoint also has no CSRF validation. This is the right call: the user has
no session yet (they are in the middle of resetting their password), so there is no CSRF
cookie to double-submit. The reset token itself serves as the unforgeable secret — an
attacker who does not have the token cannot forge a valid request.

The concern to keep in mind (noted under Finding 4.1 about the URL) is that if the
reset token were somehow exposed, this endpoint would become vulnerable. The token
being kept secret is the entire security model for this endpoint.

---

## Area 3 — Token Entropy and Expiry

"Entropy" means how unpredictable a token is — how many possible values it could be.
High entropy means an attacker guessing tokens would need to try an astronomically large
number of guesses before finding a valid one. Expiry means how long a token stays valid
after it is issued.

---

### Finding 3.1 — Reset Token Entropy Is Excellent

**Severity: Informational**

**File:** `app/api/auth/reset-password/request/route.ts:53`

```typescript
const rawToken = crypto.randomUUID();
```

A UUID v4 from `crypto.randomUUID()` provides 122 bits of randomness. To brute-force
122 bits, an attacker would need to try 2^122 ≈ 5.3 × 10^36 guesses. Even at one
trillion guesses per second, this would take longer than the age of the universe. Entropy
is not a problem here.

**The one concern:** bcrypt has an input limit of 72 bytes. A UUID v4 is 36 characters
(32 hex digits and 4 hyphens), which is 36 bytes — safely under the limit. No truncation
occurs.

---

### Finding 3.2 — Reset Token Is in the URL and Can Leak Through Multiple Channels

**Severity: Medium**

**Files:**
- `app/api/auth/reset-password/request/route.ts:65` (where the URL is constructed)
- `app/(auth)/reset-password/confirm/page.tsx:11` (where the URL is consumed)

**What happens:**

The reset token is delivered as a URL query parameter:

```
http://localhost:3000/reset-password/confirm?token=550e8400-e29b-41d4-a716-446655440000
```

This is the standard approach used by most systems, but it carries specific risks:

1. **Browser history.** The full URL, including the token, is saved in the browser's
   history. Anyone with access to the browser (a partner, a coworker, a public computer)
   can find the URL and reuse the token if it has not yet expired.

2. **Server access logs.** Web servers typically log the full request URL. If your
   hosting provider, CDN, or reverse proxy logs incoming request URLs (most do by
   default), the reset token is now in those logs. Logs are often retained for weeks or
   months and may have weaker access controls than the application itself.

3. **Referer header.** If the confirmation page loads ANY external resource — an
   analytics pixel, a font from Google Fonts, a monitoring script — the browser sends a
   `Referer` header containing the current URL, including the token. The page in this
   codebase appears to load no external resources, so this is not an immediate problem,
   but it is a fragile property that can break silently if a third-party script is ever
   added.

The token expiry (1 hour) limits the damage window but does not eliminate the risk —
an attacker who finds the token in browser history within that hour can use it.

**Partial mitigations (short of a full redesign):**
- After the token is used, replace the URL in the browser's history using
  `window.history.replaceState({}, "", "/reset-password/confirm")` — this removes the
  token from the history entry after it has been consumed.
- Consider using a `POST` body to submit the token rather than a `GET` parameter.
  The page could read the token from the URL on load, immediately remove it from the
  URL via `replaceState`, and hold it in component state for the form submission.
  The current code in `page.tsx` uses `setToken(tokenFromUrl)` on line 13 — the token
  is already in React state. Adding `replaceState` after that line would clean the URL.

---

### Finding 3.3 — bcrypt Cost Factor Is Inconsistent Between Passwords and Tokens

**Severity: Informational**

**Files:**
- Passwords: `app/api/auth/signup/route.ts:46` — cost 12
- Reset tokens: `app/api/auth/reset-password/request/route.ts:54` — cost 10

Cost 12 = 4096 internal bcrypt iterations. Cost 10 = 1024 iterations. A cost-10 hash
is ~4× faster to crack than a cost-12 hash.

For reset tokens (122 bits of entropy, one-time use, 1-hour expiry) this does not matter
— no attacker can brute-force 2^122 values regardless of how fast bcrypt runs. For
passwords (user-chosen, potentially guessable), cost 12 is the right call.

The inconsistency is not a vulnerability, but the lower cost factor on tokens also
contributes to Finding 5.1 (the bcrypt scan is slower when many tokens exist, and cost
10 per comparison is the unit of that slowness).

---

## Area 4 — Race Conditions on the Rate Limiter

---

### Finding 4.1 — In-Memory Rate Limiter Does Not Work in Production Deployments

**Severity: Medium**

**File:** `lib/rate-limit.ts`

**What happens:**

The rate limiter uses a plain JavaScript `Map` stored in module memory:

```typescript
// Line 7
const store = new Map<string, RateLimitEntry>();
```

This Map lives in one Node.js process. In a development server (a single process), it
works exactly as intended. In production — on Vercel, AWS Lambda, or any autoscaled
deployment — each function invocation runs in a separate isolated process (or even a
separate container). Each process has its own empty Map.

The consequence: an attacker can send 5 simultaneous login requests. If those requests
land on 5 different serverless instances, each instance sees 1 request against a fresh
counter. All 5 are allowed. The rate limit is never triggered.

The code acknowledges this with the comment on line 6: "In-memory store — resets on
server restart. Fine for dev/prototype." This is honest documentation. The account
lockout (lines 67–82 in the login handler) IS database-backed and DOES work across
instances — but IP-based rate limiting, which is the first line of defence, does not.

A secondary issue: the Map is never pruned. Entries with `resetAt` in the past stay in
the Map forever. Under sustained traffic, this is a slow memory leak.

**The fix for production:**

Replace the in-memory store with a shared, external store. Redis is the standard choice.
Upstash Redis is specifically designed for serverless environments (HTTP-based, no
persistent connection required). The interface change would be minimal: replace
`store.get/set` with Redis `GET/SETEX` operations.

```typescript
// The external interface stays the same; only the backing store changes.
// checkRateLimit(key, limit, windowMs) → RateLimitResult
```

---

### Finding 4.2 — No Rate Limiting on the Signup Endpoint

**Severity: Low**

**File:** `app/api/auth/signup/route.ts`

The signup endpoint has no rate limiting. An attacker can send thousands of signup
requests using different email addresses. Each request that reaches bcrypt hashing costs
the server ~300ms of CPU, which provides some natural throttling, but there is no
explicit limit.

In a system with email verification on signup, this becomes a vector for email spam. In
this codebase, signup logs nothing to an email service yet — but when that changes, this
endpoint could be abused to send unsolicited emails via your sending domain, which can
damage deliverability reputation.

**The fix:** Apply the same `checkRateLimit` pattern used in the login handler, keyed by
IP address.

---

## Area 5 — What Happens When the Email Service Fails

---

### Finding 5.1 — Token Is Committed to the Database Before the Email Is Sent; Failures Leave Inconsistent State

**Severity: Medium**

**File:** `app/api/auth/reset-password/request/route.ts`

**What happens — step by step:**

```
Line 47–50: Old tokens invalidated → committed to database
Line 57–59: New token created → committed to database
Line 62–65: Email "sent" (currently just console.log)
Line 67:    Return GENERIC_RESPONSE
```

There is no transaction wrapping these steps. The database state is permanently changed
before the email is dispatched. If sending the email throws an exception, the catch
block (line 68) returns GENERIC_RESPONSE — the same message as a successful send.

The user sees: "If that email is registered, you will receive reset instructions
shortly."

But no email arrives. Their old token was already invalidated (step 1). The new token
is in the database but not in their inbox. They have no idea what happened.

When they try again, the rate limiter allows up to 3 requests per hour per IP. Each
retry causes the same sequence: old token invalidated, new token created, email send
attempted. If the email service is consistently failing, the user keeps getting the
optimistic response while no email ever arrives.

**The concrete risks:**

1. **User confusion and lockout.** The user cannot reset their password because they
   never receive the token, but the system keeps telling them to check their email.

2. **Silent data inconsistency.** The database fills with orphaned token records (used:
   false, but the token was never delivered). These tokens are valid and will pass
   authentication if someone manages to find them.

3. **No observability.** The catch block swallows the email error silently. There are
   no logs at error level, no alerts, no counter incremented. If the email service goes
   down, you will not know unless a user complains.

**The fix — minimum viable:**

Log the email failure at error level so it appears in monitoring:

```typescript
try {
  await sendResetEmail(emailNormalized, rawToken); // real email sending
} catch (emailError) {
  console.error("[PASSWORD RESET] Email send failed:", emailError);
  // Optionally: delete the token we just created, so the DB stays clean
  await prisma.passwordReset.update({
    where: { id: newReset.id },
    data: { used: true }, // invalidate it so it cannot be used
  });
  // Return a different response that tells the user to try again
  return NextResponse.json(
    { message: "We could not send the email. Please try again in a moment." },
    { status: 503 }
  );
}
```

**The fix — production standard:**

Separate token creation from email delivery by using a job queue. The handler creates
the token, enqueues an email job, and returns the generic response. The job queue retries
failed sends automatically. The user may get the email a few seconds late, but they will
get it.

---

### Finding 5.2 — Reset Token Lookup Is O(n) in Active Tokens — DoS Amplifier

**Severity: Low**

**File:** `app/api/auth/reset-password/confirm/route.ts:25–39`

**What happens:**

To validate a submitted reset token, the confirm handler fetches ALL unused, unexpired
tokens from the database:

```typescript
const resets = await prisma.passwordReset.findMany({
  where: { used: false, expiresAt: { gt: new Date() } },
  include: { user: true },
});

for (const reset of resets) {
  const match = await bcrypt.compare(token, reset.tokenHash);
  if (match) { matchedReset = reset; break; }
}
```

Each bcrypt.compare at cost 10 takes ~65ms. If there are N active tokens, a single
confirm request takes at most N × 65ms to process. With 10 active tokens that is
650ms. With 50 active tokens that is over 3 seconds.

An attacker can exploit this by abusing Finding 2.1 (no CSRF on the request endpoint)
to generate a large number of tokens for different email addresses. After flooding the
database with 100 active tokens, each confirm request now takes up to 6.5 seconds.
With enough concurrent confirm requests, the server's event loop is saturated.

The reason bcrypt is used here at all is good: it prevents someone with database read
access from using stored token hashes to forge confirmation requests. But the
implementation does not allow indexed lookup.

**The fix:**

Use a fast cryptographic hash (SHA-256) for token storage instead of bcrypt. Fast hashes
still prevent the database-compromise attack because you cannot reverse a hash to get
the original token. The trade-off is that SHA-256 is fast, meaning a leaked hash can be
brute-forced faster — but with 122 bits of entropy, that is still computationally
impossible.

```typescript
// On token creation:
const rawToken = crypto.randomUUID();
const tokenHash = createHash("sha256").update(rawToken).digest("hex");

// On token validation:
const tokenHash = createHash("sha256").update(submittedToken).digest("hex");
const reset = await prisma.passwordReset.findUnique({ where: { tokenHash } });
```

This makes token lookup O(1) with a single indexed database query, eliminating the DoS
amplification completely.

---

## Area 6 — Error Messages That Leak Information

---

### Finding 6.1 — Account Lockout Message Confirms Email Registration

**Severity: Medium**

**File:** `app/api/auth/login/route.ts:55–63`

**What happens:**

The lockout check at line 55 only runs when the user record HAS been found in the
database. This means the lockout message is only ever shown when the email IS registered.

```typescript
// This block is only reached if user != null (i.e., the email is registered)
if (user.lockedUntil && user.lockedUntil > new Date()) {
  return NextResponse.json(
    { error: "Account temporarily locked due to too many failed attempts..." },
    { status: 423 }
  );
}
```

The generic `INVALID_CREDENTIALS` response is used for everything else — correct
approach — but this lockout message bypasses it entirely and returns a distinct HTTP
status code (423 instead of 401) along with a unique error body.

An attacker's workflow:
1. Submit 10 failed login attempts for `target@example.com`
2. Watch the response — if they get "Account temporarily locked" (HTTP 423), the email is
   confirmed as registered
3. Move on to attempting to obtain the actual password (social engineering, credential
   stuffing from another breach, etc.)

**The fix — option A (hide the lockout message):**

Return `INVALID_CREDENTIALS` even for locked accounts. Users who are locked out will
receive the same message as a wrong password. The downside: they don't know why they
can't log in and may not know to check their email for the reset flow.

**The fix — option B (decouple lockout from email confirmation):**

Explain that an account matching that email MIGHT be locked, but phrase it in a way that
makes it ambiguous whether the email exists:

```
"If an account exists with that email, it may be temporarily locked. Try resetting your
password."
```

This is still somewhat informative but far less useful to an attacker than a definitive
confirmation.

**The fix — option C (accept the trade-off):**

Treat this as an acceptable UX trade-off. The attacker caused the lockout themselves by
submitting 10 failed attempts, so they already know a lot about the account. The
incremental information (email is registered) is low-value at that point. Some teams
accept this trade-off to preserve a useful UX for legitimate locked users.

---

### Finding 6.2 — Session Tokens Stored in Plaintext in the Database

**Severity: Low**

**File:** `lib/auth.ts:16–17`

**What happens:**

The session token (a UUID) is stored directly in the sessions table:

```typescript
await prisma.session.create({
  data: { userId, token: sessionToken, csrfToken, expiresAt },
});
```

When a user sends a request, the cookie value is looked up directly:

```typescript
const session = await prisma.session.findUnique({ where: { token } });
```

This means anyone with database read access has immediate access to every active session
token. They can copy a token value, paste it into a cookie, and access the account as
if they were the legitimate user — no password needed.

Compare this to how reset tokens are handled: they are hashed with bcrypt before
storage (line 54 of the reset request handler), so a database read reveals only the
hash, not the usable token.

**The fix:**

Store the SHA-256 hash of the session token in the database. When the user sends a
request, hash the cookie value and look up the hash:

```typescript
// On session creation:
const sessionToken = crypto.randomUUID(); // sent to browser as cookie
const tokenHash = createHash("sha256").update(sessionToken).digest("hex");
await prisma.session.create({ data: { userId, tokenHash, csrfToken, expiresAt } });

// On session lookup:
const tokenHash = createHash("sha256").update(cookieValue).digest("hex");
const session = await prisma.session.findUnique({ where: { tokenHash } });
```

Database read access now gives an attacker only hashes, not usable tokens. Since session
tokens are random UUIDs (122-bit entropy), the hash cannot be reversed or brute-forced.

---

### Finding 6.3 — "User Not Found" on Change-Password Is an Internal State Leak

**Severity: Informational**

**File:** `app/api/auth/change-password/route.ts:41–43`

```typescript
if (!user) {
  return NextResponse.json({ error: "User not found." }, { status: 404 });
}
```

This code runs after a successful session check, which means `session.userId` is known
to be valid. The only way `user` is null here is if the user record was deleted from the
database while their session was still active — an unusual edge case.

The message "User not found" is technically an internal state leak: it tells the caller
(who has a valid session) that their user record no longer exists while their session
does. In practice, the only person who can reach this code is an authenticated user, so
the risk is negligible — they already know they have a session.

This could be made more generic ("Something went wrong. Please log in again.") without
any downside, but it is not an urgent fix.

---

## Summary Table

| # | Finding | Severity | File(s) |
|---|---------|----------|---------|
| 1.1 | Signup timing oracle (email enumeration) | Critical | `app/api/auth/signup/route.ts:38–46` |
| 1.2 | Reset request timing oracle (email enumeration) | Critical | `app/api/auth/reset-password/request/route.ts:37–57` |
| 1.3 | Login lockout skips bcrypt, login wrong-pw adds DB write | Low | `app/api/auth/login/route.ts:55–82` |
| 2.1 | No CSRF on reset-request; email flooding possible | Medium | `app/api/auth/reset-password/request/route.ts` |
| 2.2 | No CSRF on reset-confirm; token serves same role | Informational | `app/api/auth/reset-password/confirm/route.ts` |
| 3.1 | Reset token entropy is excellent (122 bits) | Informational | `app/api/auth/reset-password/request/route.ts:53` |
| 3.2 | Reset token exposed in URL — browser history, logs, Referer | Medium | `reset-password/request/route.ts:65`, `confirm/page.tsx:11` |
| 3.3 | bcrypt cost 10 for tokens vs 12 for passwords | Informational | `signup/route.ts:46`, `reset-password/request/route.ts:54` |
| 4.1 | In-memory rate limiter bypassed on serverless / multi-process | Medium | `lib/rate-limit.ts` |
| 4.2 | No rate limiting on signup endpoint | Low | `app/api/auth/signup/route.ts` |
| 5.1 | Email failure leaves inconsistent DB state; user sees false success | Medium | `app/api/auth/reset-password/request/route.ts:47–69` |
| 5.2 | Token lookup is O(n) × bcrypt; DoS amplifier | Low | `app/api/auth/reset-password/confirm/route.ts:25–39` |
| 6.1 | Lockout message confirms email is registered | Medium | `app/api/auth/login/route.ts:55–63` |
| 6.2 | Session tokens stored in plaintext in the database | Low | `lib/auth.ts:16–17` |
| 6.3 | "User not found" leaks internal state (post-auth, low risk) | Informational | `app/api/auth/change-password/route.ts:41–43` |

---

## Recommended Fix Priority

**Fix immediately (Critical):**
1. Add timing equalization to signup (Finding 1.1) — one `await bcrypt.hash` call
2. Add timing equalization to reset-password request (Finding 1.2) — same pattern

**Fix before production launch (Medium):**
3. Add per-email rate limiting and CAPTCHA to reset request (Finding 2.1)
4. Clean token from URL after it is read into state (Finding 3.2)
5. Replace in-memory rate limiter with Redis (Finding 4.1)
6. Handle email service failure with proper error logging and state rollback (Finding 5.1)
7. Decide on lockout message strategy (Finding 6.1) — even a comment explaining the
   trade-off decision is valuable

**Fix when the system matures (Low):**
8. Add rate limiting to signup (Finding 4.2)
9. Replace bcrypt token scan with SHA-256 indexed lookup (Finding 5.2)
10. Hash session tokens before database storage (Finding 6.2)
