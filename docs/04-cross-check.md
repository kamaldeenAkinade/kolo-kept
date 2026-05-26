# Cross-Check Audit — Verification, Disagreements & New Findings

This document independently verifies every finding in `docs/03-audit.md` against the
actual source code, identifies nuances the original audit missed, and adds new findings
focused on enumeration attacks and token security.

**Methodology:** Every claim in the original audit was traced to specific line numbers in
the source, tested for logical accuracy, and evaluated for severity calibration. Then the
codebase was re-examined with fresh eyes for issues the audit did not flag.

---

## Part 1 — Audit Verification

All 15 findings in the original audit are **factually accurate**. The line numbers,
descriptions of behaviour, and severity assessments are correct. Specifically:

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| 1.1 | Signup timing oracle | **Confirmed** | Lines 38–44 return immediately; line 46 runs bcrypt.hash. The ~300ms gap is real. |
| 1.2 | Reset request timing oracle | **Confirmed** | Lines 42–44 return immediately; lines 47–67 run DB writes + bcrypt.hash. Real gap. |
| 1.3 | Login lockout skips bcrypt | **Confirmed** | Lines 55–63 return 423 before line 65 (bcrypt.compare). |
| 2.1 | No CSRF on reset-request | **Confirmed** | No `validateCsrf` call anywhere in request/route.ts. |
| 2.2 | Reset confirm no CSRF (by design) | **Confirmed** | Token is the secret; no session to protect. Correct design. |
| 3.1 | Reset token entropy excellent | **Confirmed** | `crypto.randomUUID()` = 122 bits. |
| 3.2 | Token in URL exposure | **Confirmed** | `page.tsx:11` reads from URL. No `replaceState` call exists. |
| 3.3 | bcrypt cost inconsistency | **Confirmed** | cost 12 (signup) vs cost 10 (reset token). Acceptable as noted. |
| 4.1 | In-memory rate limiter broken in serverless | **Confirmed** | `lib/rate-limit.ts:7` uses a module-level Map. |
| 4.2 | No rate limiting on signup | **Confirmed** | No `checkRateLimit` call in signup/route.ts. |
| 5.1 | Email failure leaves inconsistent state | **Confirmed** | Token created (line 57–59) before email (line 62–65). No rollback. |
| 5.2 | Token lookup O(n) × bcrypt | **Confirmed** | `confirm/route.ts:25–40` — findMany + linear scan with bcrypt.compare. |
| 6.1 | Lockout message confirms registration | **Confirmed** | Lines 55–63 return 423 with specific message, only reachable when user exists. |
| 6.2 | Session tokens in plaintext DB | **Confirmed** | `lib/auth.ts:16–17` stores raw token. Lines 65–68 look up by raw token. |
| 6.3 | "User not found" internal state leak | **Confirmed** | `change-password/route.ts:41–43`. Low risk as noted. |

### Minor Corrections

1. **Finding 3.1 — bcrypt 72-byte limit analysis.** The audit correctly notes the UUID
   (36 bytes) is under the limit. However, `bcryptjs` (the library used) does NOT enforce
   the 72-byte limit in the same way as native bcrypt — it silently truncates at 72
   bytes. Since 36 < 72, this is not an issue, but the mechanism matters if longer tokens
   were ever used. No change to severity.

2. **Finding 6.2 — fix suggestion.** The audit recommends SHA-256 for session token
   hashing. The `tokenHash` field would need to be added to the Session model schema
   (`prisma/schema.prisma:27`). The audit does not flag that this requires a DB schema
   migration. Informational.

---

## Part 2 — Nuances the Audit Missed

These are not new findings — they are additional consequences or angles within issues
the audit already identified.

### 2a — O(n) Token Lookup Creates a Timing Oracle for Token Validity (Related to 5.2)

**File:** `app/api/auth/reset-password/confirm/route.ts:33–40`

The audit flags this as a DoS amplifier but misses the timing oracle:

- A **valid** token matches in the first bcrypt.compare iteration — response in ~65ms.
- An **invalid** token iterates through ALL N active tokens — response in N × 65ms.

If an attacker obtains a token candidate (from logs, browser history, intercepted email),
they can confirm it is valid, unexpired, and unused by measuring the response time of a
confirm request. This is a binary oracle: fast = valid, slow = invalid.

**Practical exploitability:** Low. The attacker needs a token candidate first. But if
they have one (e.g., from Finding 3.2 or the new Finding B below), the oracle removes
all guesswork about token state.

### 2b — Reset Confirm Has No Rate Limiting (Related to 4.2 / 5.2)

**File:** `app/api/auth/reset-password/confirm/route.ts`

The audit flags missing rate limiting on signup (4.2) but not on the confirm endpoint.
The confirm endpoint is unrated-limited, meaning:
- Each request costs N × 65ms of CPU (bcrypt scans)
- An attacker can amplify CPU consumption by first generating many tokens (via the
  un-CSRF-protected request endpoint — Finding 2.1), then sending concurrent confirm
  requests with invalid tokens
- Each confirm request scans all N tokens at 65ms each

The fix is the same as Finding 5.2 suggests: switch to SHA-256 indexed lookup. Combined
with per-IP rate limiting on the confirm endpoint as a defence-in-depth measure.

### 2c — The Timing Oracle on Confirm Affects All Token Statuses (Related to 3.2)

The audit's Finding 3.2 (token in URL) and Finding 5.2 (O(n) lookup) are discussed in
isolation. Combined, they create a multi-step attack:

1. Attacker sees token `T` in browser history or logs
2. Attacker sends confirm request with `T` — measures response time
3. If response is fast (~65ms): token is valid, attacker uses it
4. If response is slow (N × ~65ms + network): token is invalid or already used

The audit's proposed SHA-256 fix for Finding 5.2 would also eliminate this oracle by
making lookup O(1) regardless of token validity.

### 2d — Change-Password Missing Session Rotation (Noted by Audit Only Implicitly)

**File:** `app/api/auth/change-password/route.ts:53–57`

The audit mentions in Finding 5.1 that the confirm endpoint deletes all sessions
(confirm/route.ts:64–66). But the audit does not flag that **change-password does NOT
rotate sessions**. After a password change:

```
Line 53: const newPasswordHash = await bcrypt.hash(newPassword, 12);
Line 54–57: await prisma.user.update({ data: { passwordHash: newPasswordHash } });
Line 59: return NextResponse.json({ ok: true });
```

No session deletion. No new session creation. The old session token remains valid.

Compare with confirm/route.ts — which does delete all sessions before issuing a new one.

**Why this matters:** If a user changes their password because the old one was
compromised, the attacker's existing session (obtained via malware, session theft, or
while using the old password) continues to work indefinitely. The password change is
ineffective against active session hijackers.

This is arguably a variation of token-security concern in Area 6, and should be
considered when implementing Finding 6.2 (session token hashing).

---

## Part 3 — New Findings

### New Finding A — IP Spoofing Via Client-Controlled Headers

**Severity: Medium**

**File:** `lib/auth.ts:85–91`

```typescript
export function getClientIp(request: NextRequest): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("x-real-ip") ??
    "127.0.0.1"
  );
}
```

**What happens:**

The function trusts two HTTP headers that the client controls: `x-forwarded-for` and
`x-real-ip`. An attacker can set arbitrary values for these headers on every request:

```http
POST /api/auth/login HTTP/1.1
x-forwarded-for: 1.2.3.4
```

```http
POST /api/auth/login HTTP/1.1
x-forwarded-for: 5.6.7.8
```

Each request is rate-limited against a different key (`login:1.2.3.4` followed by
`login:5.6.7.8`). The rate limiter never triggers. This bypass works in ALL deployment
scenarios:

| Deployment | What happens |
|-----------|-------------|
| `next dev` (single process) | Attacker controls the header directly. Rate limiter sees a new IP per request. |
| Direct Node.js (no proxy) | Same — `x-forwarded-for` comes from the client. |
| Behind Vercel Edge | Vercel APPENDS to `x-forwarded-for`. The first IP in the chain is Vercel's trusted value. **Spoofing does not work here.** |
| Behind nginx with `proxy_set_header X-Real-IP $remote_addr;` | Nginx overwrites `x-real-ip`. Spoofing fails for that header, but `x-forwarded-for` may still be client-controlled if nginx does not strip it. |

**Why the audit missed it:**

Finding 4.1 correctly identifies that the rate limiter is broken in serverless (each
instance has its own empty Map). But it does not examine whether the rate limiter works
within a single process when the IP identity is attacker-controlled. The answer is: it
does not — the IP key itself is untrustworthy.

**The fix:**

Replace the header-based approach with `request.ip` (Next.js provides this from the
platform's trusted source):

```typescript
export function getClientIp(request: NextRequest): string {
  // request.ip is provided by the platform (Vercel, Node.js runtime) from the
  // actual TCP connection. It cannot be spoofed by client headers.
  return request.ip ?? "127.0.0.1";
}
```

If proxy support is required (e.g., behind a load balancer), enumerate the trusted proxy
CIDR ranges and only accept `x-forwarded-for` from those ranges.

---

### New Finding B — Raw Reset Token Logged to Console

**Severity: Medium**

**Files:**
- `app/api/auth/reset-password/request/route.ts:62–65`

```typescript
console.log(
  `\n[PASSWORD RESET TOKEN] Email: ${emailNormalized} | Token: ${rawToken}\n` +
  `Reset URL: http://localhost:3000/reset-password/confirm?token=${rawToken}\n`
);
```

**What happens:**

The raw, unhashed reset token is written to stdout. In production:

| Platform | Exposure |
|----------|----------|
| Vercel | Logs are visible in the Vercel dashboard to all team members. Vercel retains logs for a rolling window. |
| AWS Lambda | Logs go to CloudWatch Logs, which may have different access controls than the application DB. |
| Docker / K8s | Logs go to `docker logs` or a log aggregator (Datadog, Splunk, etc.), often with broader access. |

Anyone with read access to these logs can:
1. Read the raw reset token directly (no cracking needed — it's plaintext in the log line)
2. Use it at the confirm endpoint before it expires (1 hour)
3. Change the victim's password and take over the account

The audit identifies the token-in-URL problem (Finding 3.2: browser history, Referer
header, server logs) but does not mention this independent exposure channel. The two
channels are distinct:
- Finding 3.2: token leaked _after_ delivery (in the URL during consumption)
- This finding: token leaked _during generation_ (logged before delivery)

**Relationship to other findings:**

This finding combines with:
- **Finding 2.1 (CSRF on reset-request)** — an attacker can trigger reset requests for
  any email, generating log entries with that user's reset token
- **Finding 5.1 (email failure)** — if the email fails, the token is in the DB and in
  the logs, but was never delivered to the user. A log reader can use it.

**The fix — minimum:**
Remove or comment out the `console.log` before production deployment.

**The fix — better:**
If debug logging is needed, log only the email (not the token), or log a hash of the
token, or use a debug-only flag:

```typescript
if (process.env.NODE_ENV === "development") {
  console.log(`[PASSWORD RESET] Request for ${emailNormalized}`);
}
```

---

### New Finding C — Session Not Rotated on Password Change

**Severity: Medium**

**File:** `app/api/auth/change-password/route.ts:53–59`

**What happens:**

When a password is changed via the change-password endpoint, the existing session is not
invalidated:

```typescript
const newPasswordHash = await bcrypt.hash(newPassword, 12);
await prisma.user.update({
  where: { id: session.userId },
  data: { passwordHash: newPasswordHash },
});
// Session deletion is MISSING here
return NextResponse.json({ ok: true });
```

Contrast with the reset-password confirm endpoint (`confirm/route.ts:64–66`), which
correctly deletes all sessions:

```typescript
prisma.session.deleteMany({ where: { userId: matchedReset.userId } }),
```

**Attack scenario:**

1. Attacker obtains a user's password (phishing, data breach, credential stuffing)
2. Attacker logs in — a session token is stored on attacker's device
3. Victim notices suspicious activity and changes their password
4. Victim assumes the attacker is locked out
5. Attacker's session token is still valid — they retain access indefinitely

**The fix:**

Delete all existing sessions for the user after a password change, then create a new
session (matching the behaviour in confirm/route.ts):

```typescript
const newPasswordHash = await bcrypt.hash(newPassword, 12);

await prisma.$transaction([
  prisma.user.update({
    where: { id: session.userId },
    data: { passwordHash: newPasswordHash },
  }),
  prisma.session.deleteMany({ where: { userId: session.userId } }),
]);

// Create a new session for the current user
const { sessionToken, csrfToken } = await createSession(session.userId);
const response = NextResponse.json({ ok: true });
applySessionCookies(response, sessionToken, csrfToken);
return response;
```

---

### New Finding D — Confirm Endpoint Token Brute-Force Is Unthrottled

**Severity: Low**

**File:** `app/api/auth/reset-password/confirm/route.ts:7–79`

The confirm endpoint accepts token + password submissions with no rate limiting. While
the 122-bit entropy makes brute-forcing the token computationally impossible, the
unthrottled endpoint creates two concrete risks:

1. **CPU DoS amplification.** With Finding 5.2 (O(n) × bcrypt), each confirm request
   costs N × 65ms. An attacker sending many requests can saturate the server's event
   loop. This is a multiplier on top of Finding 5.2.

2. **Password brute-force on a known token.** If an attacker obtains a valid token (via
   Finding 3.2, New Finding B, or any other means), they can submit unlimited password
   guesses for that token. Each attempt that fails returns "invalid or has expired" —
   the token is not consumed on failure, so the attacker can try thousands of passwords.

   Wait — let me verify this. Looking at confirm/route.ts:
   - It fetches all unused, unexpired tokens
   - It iterates and tries bcrypt.compare against each one
   - If no match, returns "invalid or has expired" (line 44)
   - The token is NOT marked as used on an invalid attempt
   
   Yes — an attacker with a valid token can brute-force the new password on the confirm
   endpoint with no rate limit.

**Mitigation:** Add per-IP and per-token rate limiting to the confirm endpoint. After a
few failed attempts with the same token, mark it as used to prevent further guessing.

---

## Part 4 — Severity Re-Calibrations

The original audit's severities are well-calibrated. However, the cross-check suggests
two adjustments:

| Finding | Original | Cross-Check | Reason |
|---------|----------|-------------|--------|
| 4.1 (in-memory rate limiter) | Medium | **Medium → Medium** | Confirmed. New Finding A (IP spoofing) makes this worse in aggregate, but the original severity stands. |
| 5.2 (O(n) token lookup) | Low | **Low → Medium** | Not just a DoS amplifier. It also creates a timing oracle for token validity (Finding 2a above) and the unthrottled confirm endpoint (Finding D) makes the CPU exhaustion easier. The combination of oracle + DoS + no rate limit raises the practical risk. |

Adjusted:

| Finding | Severity |
|---------|----------|
| 1.1 Signup timing oracle | Critical |
| 1.2 Reset request timing oracle | Critical |
| **A** IP spoofing bypasses rate limiter | Medium |
| **B** Raw reset token in console.log | Medium |
| **C** No session rotation on change-password | Medium |
| **D** Confirm endpoint unthrottled (brute-force) | Low |
| 2.1 No CSRF on reset-request | Medium |
| 3.2 Token in URL | Medium |
| 4.1 In-memory rate limiter (multi-process) | Medium |
| 5.1 Email failure inconsistent state | Medium |
| **5.2 → adjusted** O(n) × bcrypt lookup | **Medium** (was Low) |
| 6.1 Lockout message confirms registration | Medium |
| 1.3 Login lockout skips bcrypt timing | Low |
| 4.2 No rate limiting on signup | Low |
| 6.2 Session tokens in plaintext DB | Low |
| 6.3 "User not found" internal state leak | Informational |
| 2.2 No CSRF on reset-confirm (by design) | Informational |
| 3.1 Reset token entropy excellent | Informational |
| 3.3 bcrypt cost inconsistency | Informational |

---

## Part 5 — Summary of New Findings

| # | Finding | Severity | File(s) |
|---|---------|----------|---------|
| A | IP spoofing via `x-forwarded-for`/`x-real-ip` bypasses rate limiter | Medium | `lib/auth.ts:85–91` |
| B | Raw reset token written to `console.log` (accessible in production logs) | Medium | `app/api/auth/reset-password/request/route.ts:62–65` |
| C | Password change does not invalidate existing sessions | Medium | `app/api/auth/change-password/route.ts:53–59` |
| D | Confirm endpoint has no rate limiting (token/password brute-force) | Low | `app/api/auth/reset-password/confirm/route.ts` |

### Nuances (Sub-Findings Within Existing Issues)

| # | Related To | Description |
|---|-----------|-------------|
| 2a | 5.2 | O(n) × bcrypt also creates a timing oracle for token validity, not just a DoS amplifier |
| 2b | 4.2 / 5.2 | Reset confirm endpoint has no rate limiting, compounding the O(n) DoS |
| 2c | 3.2 + 5.2 | Token-in-URL + O(n) timing oracle enables multi-step token validity confirmation |
| 2d | 6.2 | Change-password does not rotate sessions (inconsistent with confirm endpoint behaviour) |

---

## Part 6 — Codebase Observations (No Severity)

These are design notes that affect trust in the token and enumeration protections, but
are not vulnerabilities themselves.

1. **The double-submit CSRF pattern depends on absence of XSS.** The `csrf-token` cookie
   is readable by JavaScript (not httpOnly, by design). Any XSS vulnerability anywhere
   in the application leaks the CSRF token. The session cookie (httpOnly) remains
   protected from direct JS access, but the attacker can use the leaked CSRF token to
   forge state-changing requests that the browser will authenticate with the session
   cookie.

2. **All entropy sources are `crypto.randomUUID()`.** Sessions, CSRF tokens, and reset
   tokens all use `crypto.randomUUID()` (128-bit UUID v4, 122 bits of entropy). This is
   cryptographically sound and consistent.

3. **The middleware blocks unauthenticated API access correctly.** The middleware at
   `middleware.ts:36` allows public API routes through; all other `/api/*` requests
   without a session cookie get a 401 response. This is correct for the routing layer,
   though route handlers still perform their own DB-backed session validation.

4. **No account deletion endpoint exists.** There is no `DELETE /api/auth/account`
   endpoint. Account enumeration via deletion attempts is not a concern in this codebase.

5. **The signup auto-login is acceptable for a prototype.** The audit flags no rate
   limiting on signup (Finding 4.2). The auto-login without email verification
   compounds this — each signup creates a permanent user record AND an active session.
   For production, email verification should gate account activation, and the first
   session should only be created after verification.

---

## Part 7 — Cross-Reference: Attack Chains

The following attack chains show how multiple findings combine:

### Chain 1: Email Enumeration via Timing

```
1. Attacker sends signup request for target@example.com with strong password
2. Server checks existing user (fast → ~5ms) OR runs bcrypt.hash (slow → ~300ms)
   [Finding 1.1 — Critical]
3. Attacker measures response time → knows if email is registered
4. Attacker sends login request for same email with wrong password
5. If locked → 423 response confirms registration [Finding 6.1 — Medium]
6. Attacker now has confirmed the email is registered
```

### Chain 2: Token Hijacking via Log Exposure

```
1. Attacker triggers reset request for victim@example.com
   [Finding 2.1 — No CSRF, No per-email rate limit]
2. Server logs raw token to stdout [New Finding B — Medium]
3. Attacker reads logs (CloudWatch, Vercel dashboard, etc.)
4. Attacker has raw reset token — valid for 1 hour
5. Attacker calls confirm endpoint with token
6. If response is fast (breaks on first bcrypt match) → token is valid
   [Finding 2a — O(n) timing oracle]
7. Attacker sets new password → account compromised
```

### Chain 3: Rate Limiter Triple Bypass

```
1. Attacker spoofs x-forwarded-for header per request
   [New Finding A — Medium: bypasses IP identity]
2. Even without spoofing, in serverless each instance has empty Map
   [Finding 4.1 — Medium: bypasses shared state]
3. Signup endpoint has no rate limiting at all
   [Finding 4.2 — Low: no limit to bypass]
4. Attacker can send unlimited requests to all auth endpoints
```

---

## Part 8 — Recommended Fix Priority (Amended)

**Fix immediately (Critical):**
1. Add timing equalization to signup (Finding 1.1)
2. Add timing equalization to reset-password request (Finding 1.2)

**Fix before production launch (Medium — New):**
3. Fix IP spoofing: use `request.ip` instead of client headers (New Finding A)
4. Remove or gate `console.log` of raw reset tokens (New Finding B)
5. Rotate sessions on password change (New Finding C)
6. Recalibrate severity of O(n) token lookup and fix with SHA-256 (Finding 5.2 → Medium)

**Fix before production launch (Medium — Existing, reordered):**
7. Add per-email rate limiting and CAPTCHA to reset request (Finding 2.1)
8. Clean token from URL via `replaceState` (Finding 3.2)
9. Replace in-memory rate limiter with Redis (Finding 4.1)
10. Handle email service failure with proper error logging and rollback (Finding 5.1)
11. Decide on lockout message strategy (Finding 6.1)
12. Add rate limiting to confirm endpoint (New Finding D)

**Fix when the system matures (Low):**
13. Add rate limiting to signup (Finding 4.2)
14. Hash session tokens before database storage (Finding 6.2)
