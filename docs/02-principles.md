# Authentication Principles — Mapped to This Codebase

This document takes six core security principles and shows exactly where they live in
the code. Every rule is defined first in plain language, then traced to specific lines.
Think of each principle as a habit of mind, not a one-time checklist item.

---

## 1. Least Privilege

**What it means in plain language:**
Every part of the system should be able to see and do only the minimum it actually
needs to get its job done — nothing extra. If a function only needs to know whether a
user exists, it should not also be loading their password hash, their email, or anything
else. The same applies to what operations are allowed (read vs. write) and who is allowed
to call them (only the owner of a resource, not anyone who is logged in).

**The mental model:** Imagine you hire a contractor to fix your front door. You give them
a key to the front door, not a master key to every room. If the key gets copied, the
damage is limited.

**Where you see it in this code:**

- `app/api/auth/signup/route.ts:34–36` — When checking for an existing email, the query
  uses `select: { id: true }`. It only retrieves the user's ID, even though the full
  user record (including passwordHash) is in the same table. There is no reason to load
  the hash just to check existence, so it isn't loaded.

- `app/api/auth/change-password/route.ts:37–39` — Similarly, only `passwordHash` is
  selected when fetching the user for the password comparison. No email, no sessions,
  no other fields.

- `lib/auth.ts:103–105` — `validateCsrf` selects only `{ csrfToken, expiresAt }` from
  the session row. It does not load the full session (which would include the userId and
  the joined user object). It only needs two fields, so it only asks for two fields.

- `app/api/entries/route.ts:11–16` — The entries GET query uses
  `where: { userId: session.userId }`. A logged-in user can only ever see their own
  entries. The filter is applied at the database level — it is not "load everything, then
  filter in code." The database enforces the boundary.

- `app/api/entries/[id]/route.ts:21–25` — Before deleting an entry, the handler fetches
  only `{ userId: true }` and then checks `entry.userId !== session.userId`. A user can
  only delete their own entries, even if they know someone else's entry ID. Knowing the
  ID is not enough — ownership is verified.

---

## 2. Defense in Depth

**What it means in plain language:**
No single lock protects the house. You have a gate, then a front door, then an alarm.
If one layer fails or is bypassed, the next layer still catches the attacker. Depth means
layers are independent of each other — breaking through one does not automatically grant
access to the others.

**The mental model:** A bank vault is not protected by one big lock. There is a security
guard, a time-locked door, a combination lock, and a camera. Each one independently
slows or stops an attacker.

**Where you see it in this code:**

- **Layer 1 — Middleware routing check** (`middleware.ts:38–45`): The middleware runs on
  every request before any route handler sees it. It checks for the presence of the
  session cookie. If it is missing, API requests get a 401 and page requests get
  redirected to `/login`. This is a fast, edge-runtime check. It does not hit the database.

- **Layer 2 — Server component layout guard** (`app/(dashboard)/layout.tsx:11–12`):
  Even if a request somehow passed middleware, the dashboard layout calls `getSession()`
  on the server and does a full database lookup. If the session is expired or forged,
  `redirect("/login")` fires before any page content is rendered.

- **Layer 3 — Route handler session check**: Every protected API route (entries, goal,
  change-password, logout-everywhere) calls `getSession(request)` and returns a 401 if
  it is null. `app/api/entries/route.ts:6–9` is a clear example. Even if layers 1 and 2
  were somehow bypassed, the route still verifies the session independently.

- **Layer 4 — CSRF validation on mutating requests** (`lib/auth.ts:93–109`): All state-
  changing routes (POST, DELETE) validate a CSRF token before doing anything else.
  `app/api/entries/[id]/route.ts:9–11` and `app/api/auth/logout/route.ts:6–8` show this
  pattern. A valid session cookie alone is not sufficient for a write operation.

- **Two independent brute-force defenses:**
  - Rate limiting by IP: `app/api/auth/login/route.ts:19–29` blocks after 5 attempts
    per 15-minute window per IP address.
  - Account lockout by user record: `app/api/auth/login/route.ts:54–62` locks the
    account for 1 hour after 10 failed attempts. These two systems are independent.
    Switching IP addresses defeats rate limiting but not lockout. Using a single IP
    defeats lockout for one user but triggers rate limiting.

- **Middleware check vs. DB validation are intentionally separate** (see the comment at
  `middleware.ts:16–18`): The middleware only checks cookie presence. The real
  validation — database lookup, expiry comparison — happens in `lib/auth.ts:65–76`.
  This is a deliberate design split, not an oversight.

---

## 3. Fail Securely

**What it means in plain language:**
When something goes wrong — an unexpected error, a missing value, an expired token — the
system should fail in a way that denies access, not one that accidentally grants it.
"Fail open" (allowing access when uncertain) is the dangerous version. "Fail closed"
(denying access when uncertain) is the secure version.

**The mental model:** A locked door with a broken handle is still locked. You don't want
a door that swings open when the handle breaks.

**Where you see it in this code:**

- `lib/auth.ts:63` — `getSession` returns `null` if there is no token. It does not
  return a partial session, a guest session, or throw — it returns null, and every
  caller treats null as "not authenticated."

- `lib/auth.ts:71–74` — If the session is found in the database but its `expiresAt` is
  in the past, the session is deleted and null is returned. An expired session is treated
  identically to a missing session. The system does not allow a "close enough" login.

- `lib/auth.ts:96–97` — `validateCsrf` returns `false` immediately if the CSRF header
  is missing. It does not try to proceed without it, and callers (`app/api/auth/logout/route.ts:6–8`)
  treat false as a hard stop.

- `app/api/auth/reset-password/request/route.ts:68–69` — Even when the server throws
  an unexpected error inside the catch block, the response is the same generic message
  as a success. The system never leaks error details and never exposes whether processing
  succeeded or failed.

- `app/api/auth/login/route.ts:94–99` — The outer try/catch returns a generic 500
  message, not a stack trace or database error. The same pattern appears in signup,
  change-password, and entries routes. Exceptions are swallowed at the boundary —
  they never travel to the client.

- `app/api/entries/[id]/route.ts:24–26` — If an entry does not exist, or exists but
  belongs to a different user, the response is the same: 404 "Entry not found." The
  system does not distinguish between "this ID doesn't exist" and "this ID exists but
  you don't own it." Either answer could help an attacker map out other users' data,
  so both are treated identically.

---

## 4. Generic Errors

**What it means in plain language:**
Error messages shown to users (and returned in API responses) should not reveal
internal system state. An attacker who gets an informative error ("that email is already
registered" or "wrong password, but the account exists") can use that information to
plan their next move. Generic errors give away nothing useful.

**The mental model:** If you ask a bank teller "does this account number exist?" a well-
trained teller says "I can't help with that request" — not "yes it exists but you don't
have access." The answer itself is the leak.

**Where you see it in this code:**

- `app/api/auth/login/route.ts:13` — The constant `INVALID_CREDENTIALS = "Invalid email
  or password."` is used for every login failure, whether the email does not exist,
  the password is wrong, or the input is missing entirely (`lines 35–37`, `51`, `81`).
  An attacker cannot use the login form to test whether an email address is registered.

- `app/api/auth/login/route.ts:44–51` — Even when the user does not exist in the
  database, bcrypt.compare is still called on a dummy hash. This prevents a timing
  attack: without this, a missing user returns faster than a wrong-password user
  (because the hash comparison is skipped), and that time difference reveals account
  existence. The comment on `line 44` explains this directly.

- `app/api/auth/signup/route.ts:38–44` — When a user tries to sign up with an email
  already in use, the response says "Unable to create account. Please try a different
  email." — not "that email is already registered." If it said the latter, an attacker
  could feed in a list of emails and learn which ones have accounts.

- `app/api/auth/reset-password/request/route.ts:13–16` — The `GENERIC_RESPONSE`
  constant is used for every possible outcome of the reset request: missing email, email
  not found, rate limited, server error, and success (`lines 34`, `45`, `67`, `69`).
  From the outside, there is no way to distinguish a registered email from an
  unregistered one by watching the reset flow.

- `app/api/auth/reset-password/request/route.ts:26–28` — When the rate limit triggers,
  the response is still 200 OK with the generic message — not 429. Returning 429 would
  reveal that the rate limiter triggered, which itself confirms a series of requests came
  from this IP.

- `app/api/entries/[id]/route.ts:24–26` — Already noted under Fail Securely, but the
  generic error principle applies here too: 404 "Entry not found" for both unauthorized
  access and genuine missing records. "Not authorized" as a message would confirm the
  entry exists, which is information.

---

## 5. Secure Defaults

**What it means in plain language:**
The starting configuration should be the most secure one. If a developer forgets to
opt into a security feature, the system should already be secure. Insecure behavior
should require explicit, deliberate action — not be the fallback.

**The mental model:** A new phone should have the lock screen enabled by default. You
should have to explicitly turn it off, not remember to turn it on.

**Where you see it in this code:**

- `lib/auth.ts:30–36` — The session cookie is set with `httpOnly: true`. This means
  JavaScript running in the browser cannot read it. An XSS attack that injects malicious
  script cannot steal the session token, because the script has no access to the cookie.
  httpOnly is the default — no one has to remember to add it.

- `lib/auth.ts:28` — `secure: isProd` makes the cookie HTTPS-only in production. This
  means the browser will not send it over an unencrypted HTTP connection. In development
  this is turned off (so local testing works), but the production default is secure.

- `lib/auth.ts:31–36` — `sameSite: "lax"` is set on the session cookie. This tells the
  browser not to send the session cookie on cross-site form submissions or requests
  initiated from other domains. This is a built-in layer of CSRF defense even before
  the double-submit token check.

- `lib/auth.ts:39–45` — The CSRF token cookie is `httpOnly: false` — this is the
  intentional, commented exception. The double-submit CSRF pattern requires client
  JavaScript to read the CSRF cookie and put its value into a header. The comment
  explicitly explains why this one cookie must be readable. Every other cookie defaults
  to httpOnly.

- `app/api/auth/signup/route.ts:46` — Passwords are hashed with bcrypt at cost factor
  12. Cost factor 12 means bcrypt runs 4096 iterations internally, making brute force
  slow. The default is a strong one — a developer would have to explicitly lower it to
  make it weaker.

- `lib/password.ts:8–37` — The password strength validator enforces minimum length (12),
  uppercase, lowercase, digits, and special characters. These are the default
  requirements — you cannot create an account without meeting them. A developer would
  have to remove these checks to allow a weak password through.

- `lib/auth.ts:5–6` — Sessions expire after 7 days. The system does not issue permanent
  sessions. A stolen session token becomes useless after 7 days without any action from
  the user.

---

## 6. Separation of Concerns Between Auth Logic and Business Logic

**What it means in plain language:**
Authentication ("who are you?") and business logic ("what can you do, and let's do it")
should live in different places. If they are mixed together, the code becomes hard to
reason about, hard to test, and easy to mess up — you might add a new feature and
accidentally skip the auth check because it was buried inside the same function.

**The mental model:** In a restaurant, the host verifies your reservation and seats you.
The waiter takes your order. The chef cooks it. Each role is separate. The chef does not
also verify reservations.

**Where you see it in this code:**

- `lib/auth.ts` exists solely to manage sessions: create them, read them, validate them,
  clear cookies. It has no business logic in it. It does not know what entries, goals, or
  settings are.

- `lib/password.ts` exists solely to validate and score password strength. It does not
  touch sessions, cookies, or database records. It is a pure function that takes a string
  and returns a result.

- `lib/rate-limit.ts` exists solely to track and enforce request rate limits. It takes a
  key, a limit, and a window, and returns allowed/denied. It knows nothing about users or
  auth.

- Route handlers are the point where auth and business logic meet — but they are kept in
  strict sequence. In `app/api/entries/route.ts:19–23`, the pattern is always:
  1. Check CSRF (auth concern)
  2. Check session (auth concern)
  3. Then do the business logic (create entry, validate input, write to DB)

  These steps are never interleaved. Auth is always resolved first and completely before
  any business operation begins.

- `app/(dashboard)/layout.tsx:11–12` — The layout is responsible only for the auth
  gate. It calls `getSession()` and redirects if the result is null. It does not also
  try to load entries or process forms. The page components inside the layout handle
  their own data needs.

- `middleware.ts:20–52` — The middleware only handles routing decisions based on auth
  state. It does not perform any business logic. The comment at line 16–18 makes this
  split explicit: the middleware does a "lightweight cookie-presence check for routing"
  and defers full session validation to the route handlers.

- The consequence of this separation: if you want to add a new feature (say, a notes
  route), you just call `getSession()` and `validateCsrf()` at the top of your new
  handler. The auth logic is already written, tested, and consistent. You do not have to
  re-implement it or adapt it to your feature.

---

## How the Principles Reinforce Each Other

These six principles are not independent rules — they stack and support each other:

| Principle            | Without it                                                       |
|----------------------|------------------------------------------------------------------|
| Least Privilege      | A compromised function leaks more than it needs to              |
| Defense in Depth     | One bypassed check gives full access                             |
| Fail Securely        | Errors become doors instead of walls                             |
| Generic Errors       | Error messages hand attackers a map                              |
| Secure Defaults      | Developers have to remember to add security — and they forget    |
| Separation of Concerns | Auth logic drifts, gets skipped, or gets duplicated incorrectly |

Together, they create a system where an attacker who defeats one control still faces
several others, where the code can be read and audited without confusion, and where
adding new features does not silently weaken security.
