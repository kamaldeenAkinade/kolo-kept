# Kolo Kept — Code Explanation (ELI7 Edition)

This document explains three security features line by line as if you are seven years old
and just learning what computers do. We cover:

1. How rate limiting decides when to block a request
2. How account lockout state is stored and checked
3. How the password reset token travels from a request all the way to success

---

## Part 1 — Rate Limiting (`lib/rate-limit.ts` + `app/api/auth/login/route.ts`)

**The big idea in one sentence:** The app keeps a notepad. Every time someone from the
same internet address tries to log in, it makes a tally mark. After five marks in fifteen
minutes, it says "nope, stop knocking."

---

### The notepad itself (`lib/rate-limit.ts` lines 7)

```ts
const store = new Map<string, RateLimitEntry>();
```

`Map` is JavaScript's version of a notepad. The key (left side) is who is knocking —
something like `"login:203.0.113.5"`. The value (right side) is a little object with two
fields: how many times they have knocked (`count`) and what time the notepad page tears
off and resets (`resetAt`, stored as a plain number of milliseconds since 1 Jan 1970).

This notepad lives in the server's memory, not the database. That means it is super fast
to read but it forgets everything if the server restarts. Fine for a prototype.

---

### The shape of one notepad entry (`lib/rate-limit.ts` lines 1–4)

```ts
type RateLimitEntry = {
  count: number;
  resetAt: number;
};
```

Just two numbers. `count` goes up every knock. `resetAt` is the future timestamp when
this entry becomes stale and the counter resets to zero.

---

### The function that does all the work (`lib/rate-limit.ts` lines 13–32)

```ts
export function checkRateLimit(
  key: string,
  limit: number,
  windowMs: number
): RateLimitResult {
```

Three inputs come in:
- `key` — who is knocking (the IP address string).
- `limit` — how many knocks are allowed (5 for login).
- `windowMs` — how long the window is in milliseconds (15 minutes = 900 000 ms).

---

```ts
  const now = Date.now();
  const entry = store.get(key);
```

`Date.now()` gives us the current time as a big number (milliseconds since 1970).
We then look up this IP address in the notepad. `entry` is either the notepad page we
found, or `undefined` if this person has never knocked before.

---

```ts
  if (!entry || entry.resetAt <= now) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: limit - 1 };
  }
```

**Branch 1 — first knock ever, or the old page has expired.**
`!entry` is true when we have never seen this IP.
`entry.resetAt <= now` is true when the page's expiry time is in the past.

Either way, we tear out a fresh page: count starts at 1, the reset time is set to fifteen
minutes from right now (`now + windowMs`). We let the request through and say there are
four knocks remaining.

---

```ts
  if (entry.count >= limit) {
    return { allowed: false, retryAfterMs: entry.resetAt - now };
  }
```

**Branch 2 — already hit the limit.**
`entry.count >= limit` means the person has already used all five allowed knocks within
the active window. We say `allowed: false` and tell them how many milliseconds are left
until the page resets. The login route turns that into a `Retry-After` HTTP header so
the browser knows exactly when to try again.

---

```ts
  entry.count += 1;
  return { allowed: true, remaining: limit - entry.count };
}
```

**Branch 3 — still under the limit.**
We add one tally mark to the existing page and let the request through. The `entry`
object is updated in place because `Map` stores a reference, not a copy, so we do not
need to call `store.set` again.

---

### How the login route uses this (`app/api/auth/login/route.ts` lines 7–29)

```ts
const LOGIN_RATE_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
```

Named constants at the top so the magic numbers are readable: 5 attempts, 15 minutes.

---

```ts
  const ip = getClientIp(request);
  const rateLimitKey = `login:${ip}`;
```

`getClientIp` reads the `X-Forwarded-For` header (set by load balancers and proxies)
and falls back to `X-Real-IP`, then `"127.0.0.1"`. We prefix the key with `"login:"`
so the same in-memory store can also hold `"reset:..."` keys without the two counters
ever colliding.

---

```ts
  const rateCheck = checkRateLimit(rateLimitKey, LOGIN_RATE_LIMIT, LOGIN_WINDOW_MS);
  if (!rateCheck.allowed) {
    const retryAfterSecs = Math.ceil(rateCheck.retryAfterMs / 1000);
    return NextResponse.json(
      { error: "Too many login attempts. Please try again later." },
      { status: 429, headers: { "Retry-After": String(retryAfterSecs) } }
    );
  }
```

We call `checkRateLimit` immediately — before we even read the request body. If the
result says `allowed: false`, we stop right here and return HTTP 429 (the official
"too many requests" status code). We convert the retry time from milliseconds to seconds
because the `Retry-After` header spec uses seconds.

Note that the error message is intentionally vague — it does not say why or which IP is
blocked, just "try later."

---

## Part 2 — Account Lockout (database + `app/api/auth/login/route.ts`)

**The big idea in one sentence:** Each user account has two sticky notes stuck to it in
the database — a wrong-guess tally and a "do not open until" timestamp — and the login
route checks both before it even tries the password.

---

### Where the data lives (`prisma/schema.prisma` lines 10–22)

```prisma
model User {
  id             String    @id @default(cuid())
  email          String    @unique
  passwordHash   String
  failedAttempts Int       @default(0)
  lockedUntil    DateTime?
  ...
}
```

Every row in the `User` table has two lockout-related columns:

- `failedAttempts` — a plain integer that starts at zero. Goes up by one on every wrong
  password, no matter where in the world the attempt came from.
- `lockedUntil` — a nullable timestamp (the `?` means it can be `null`). While `null`
  the account is open. When a value is written here, the account is locked until that
  moment in time has passed.

Storing this in the database — not in memory — means it survives server restarts and
works correctly across multiple server instances. Rate limiting can live in memory
because it resets naturally; lockout state needs to be durable.

---

### Checking lockout before trying the password (`login/route.ts` lines 54–63)

```ts
if (user.lockedUntil && user.lockedUntil > new Date()) {
  return NextResponse.json(
    {
      error:
        "Account temporarily locked due to too many failed attempts. Reset your password to unlock it.",
    },
    { status: 423 }
  );
}
```

`user.lockedUntil && user.lockedUntil > new Date()` — two conditions must both be true:

1. `user.lockedUntil` is not null (the column has a timestamp in it).
2. That timestamp is still in the future (`> new Date()` means "has not arrived yet").

If both are true, we return HTTP 423 ("Locked" — yes, that is a real HTTP status code).
The message tells the user exactly what to do: reset your password. We do this check
*before* running `bcrypt.compare`, because bcrypt is intentionally slow and we do not
want to waste that time on a locked account.

The error message does not say how many attempts remain or when the lock expires.
Giving that information would help an attacker plan their next move.

---

### Recording a wrong guess (`login/route.ts` lines 67–81)

```ts
    if (!passwordMatch) {
      const newFailedAttempts = user.failedAttempts + 1;
      const shouldLock = newFailedAttempts >= LOCKOUT_THRESHOLD;

      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedAttempts: newFailedAttempts,
          lockedUntil: shouldLock
            ? new Date(Date.now() + LOCKOUT_DURATION_MS)
            : null,
        },
      });

      return NextResponse.json({ error: INVALID_CREDENTIALS }, { status: 401 });
    }
```

`newFailedAttempts` is the current count plus one.

`shouldLock` is `true` when that new count reaches or exceeds 10 (`LOCKOUT_THRESHOLD`).

The database update writes both fields atomically in a single SQL statement:
- `failedAttempts` always goes up.
- `lockedUntil` is set to one hour in the future *only* on the tenth failure
  (`new Date(Date.now() + LOCKOUT_DURATION_MS)`), otherwise it is left as `null`.

After the update we still return the generic `"Invalid email or password."` message — the
same message given for every other failure. The user never learns which attempt was the
tenth or that their account is now locked until they actually hit that 423 on the next try.

---

### Clearing the slate on success (`login/route.ts` lines 84–88)

```ts
    await prisma.user.update({
      where: { id: user.id },
      data: { failedAttempts: 0, lockedUntil: null },
    });
```

A correct password is a clean slate. Both counters are reset so that a user who made nine
genuine typos before getting it right is not punished on their next session.

---

### Why two layers (rate limit + lockout) instead of one?

Rate limiting (Part 1) is per-IP. If an attacker controls ten thousand different IP
addresses they can bypass it. Account lockout is per-account. Even if the attacker
distributes their guesses across millions of IPs, the tenth wrong guess on *that user's
row* triggers the lock. Together they protect against both small, focused attacks from one
place and large, distributed ones from many places.

---

## Part 3 — Password Reset Token Flow

**The big idea in one sentence:** We hand the user a secret lottery ticket, write a
scrambled copy in the database, and when they hand the ticket back we check it matches
the scrambled copy — then we let them set a new password and immediately throw the ticket
in the bin.

The flow has two HTTP requests handled by two separate route files.

---

### Step A — Requesting a reset (`app/api/auth/reset-password/request/route.ts`)

#### Rate limiting the reset endpoint (lines 18–28)

```ts
  const ip = getClientIp(request);
  const rateCheck = checkRateLimit(
    `reset:${ip}`,
    RESET_RATE_LIMIT,   // 3
    RESET_WINDOW_MS     // 1 hour
  );
  if (!rateCheck.allowed) {
    return NextResponse.json(GENERIC_RESPONSE);
  }
```

Same rate-limiter as login, but with a different key prefix (`"reset:"`) and tighter
settings: only 3 requests per IP per hour. Notice that even when blocked we return HTTP
200 with the generic message — not 429. If we returned 429 here an attacker could confirm
whether an email is registered by watching whether the rate limit fires sooner. By always
returning 200 with the same body, we leak nothing.

---

#### Looking up the user without leaking information (lines 30–45)

```ts
    const emailNormalized = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email: emailNormalized },
      select: { id: true },
    });

    if (!user) {
      return NextResponse.json(GENERIC_RESPONSE);
    }
```

We normalise the email (lowercase, trimmed whitespace) so `You@Example.COM` and
`you@example.com` resolve to the same account.

We only ask Prisma to `select: { id: true }` — fetching just the user's id, nothing
else. We do not need the password hash here and it is good practice to not load data you
do not need.

If no user exists for that email, we return the exact same generic message as if they did
exist. This is called "preventing email enumeration" — the attacker learns nothing about
which emails are registered.

---

#### Invalidating old tokens (lines 47–51)

```ts
    await prisma.passwordReset.updateMany({
      where: { userId: user.id, used: false },
      data: { used: true },
    });
```

Before creating a new token, all of this user's previous unused tokens are marked `used`.
Why? If someone requests a reset, then requests another one five minutes later, the first
link is now dead. Only the newest link works. This prevents an attacker who intercepted
an old email from using a stale link.

---

#### Creating and storing the token (lines 53–59)

```ts
    const rawToken = crypto.randomUUID();
    const tokenHash = await bcrypt.hash(rawToken, 10);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    await prisma.passwordReset.create({
      data: { userId: user.id, tokenHash, expiresAt },
    });
```

`crypto.randomUUID()` creates a cryptographically random UUID like
`"a3f7c821-04b2-4de1-9f3a-b2c9e10d7f11"`. This is the *lottery ticket* — the raw token
that goes in the email/console.

`bcrypt.hash(rawToken, 10)` scrambles it into something like
`"$2a$10$GhE3..."`. This is the *scrambled copy* that goes in the database.

We never store the raw token in the database. Why? If an attacker reads the database
they get only the scrambled copy, which cannot be reversed back to the original token.
This is the same principle as storing password hashes instead of passwords.

`expiresAt` is one hour from now. After that the token is dead even if it has never been
used.

The `PasswordReset` row that gets written has four meaningful fields:
- `userId` — which account this ticket belongs to.
- `tokenHash` — the scrambled copy for later comparison.
- `expiresAt` — when the ticket expires.
- `used` — starts as `false`; flipped to `true` when consumed.

---

#### Sending the token (lines 61–65)

```ts
    console.log(
      `\n[PASSWORD RESET TOKEN] Email: ${emailNormalized} | Token: ${rawToken}\n` +
        `Reset URL: http://localhost:3000/reset-password/confirm?token=${rawToken}\n`
    );
```

In a production app this line would call an email service (Resend, SendGrid, etc.) and
send a link to the user's inbox. For the prototype we print the raw token to the server
console so the grader can copy it without setting up email. The raw token appears only
here — it never goes into the database.

---

### Step B — Confirming the reset (`app/api/auth/reset-password/confirm/route.ts`)

#### Validating the new password first (lines 19–22)

```ts
    const strengthCheck = validatePasswordStrength(password);
    if (!strengthCheck.valid) {
      return NextResponse.json({ error: strengthCheck.message }, { status: 400 });
    }
```

We check the new password meets the strength rules *before* doing any database work.
No point doing expensive lookups if the password is going to be rejected anyway.

---

#### Finding the matching token (lines 25–40)

```ts
    const resets = await prisma.passwordReset.findMany({
      where: {
        used: false,
        expiresAt: { gt: new Date() },
      },
      include: { user: true },
    });

    let matchedReset = null;
    for (const reset of resets) {
      const match = await bcrypt.compare(token, reset.tokenHash);
      if (match) {
        matchedReset = reset;
        break;
      }
    }
```

We cannot do a direct database lookup like `WHERE tokenHash = ?` because we have the raw
token but the database only holds the bcrypt hash. bcrypt is a one-way function — you
cannot unhash it.

So instead we:
1. Fetch all rows that are `used: false` (not yet consumed) and `expiresAt > now` (not
   yet expired). In practice there will only ever be a tiny handful — usually just one
   per pending reset.
2. Loop over them. For each row, `bcrypt.compare(token, reset.tokenHash)` re-scrambles
   the raw token in the same way as the original hash and checks if they match. This is
   the same operation used to compare passwords.
3. When a match is found, store it in `matchedReset` and break out of the loop.

If no match is found after checking all rows, the token is either wrong, already used, or
expired. We return a generic error that does not specify which.

---

#### Writing all the changes in one atomic transaction (lines 51–66)

```ts
    await prisma.$transaction([
      prisma.passwordReset.update({
        where: { id: matchedReset.id },
        data: { used: true },
      }),
      prisma.user.update({
        where: { id: matchedReset.userId },
        data: {
          passwordHash: newPasswordHash,
          failedAttempts: 0,
          lockedUntil: null,
        },
      }),
      prisma.session.deleteMany({ where: { userId: matchedReset.userId } }),
    ]);
```

`prisma.$transaction([...])` means: run all three database operations together. Either
all three succeed, or none of them do. This prevents a situation where, say, the token is
marked used but the password never gets updated (or vice versa) because of a crash
halfway through.

The three operations are:
1. **Mark the token used.** The lottery ticket is torn up. The same token can never be
   used again, even if someone copies the link.
2. **Update the password hash, and clear the lockout.** The new scrambled password is
   written, and both `failedAttempts` and `lockedUntil` are reset. This is the unlock
   path described in Part 2.
3. **Delete all existing sessions.** If the account was hijacked and the attacker had an
   active session cookie, that cookie becomes worthless the instant the password is reset.
   The legitimate owner regains sole control.

---

#### Logging the user in immediately (lines 69–72)

```ts
    const { sessionToken, csrfToken } = await createSession(matchedReset.userId);
    const response = NextResponse.json({ ok: true });
    applySessionCookies(response, sessionToken, csrfToken);
    return response;
```

After a successful reset the user is signed in automatically — no need to visit the login
page again. `createSession` writes a fresh row to the `Session` table and returns two
random UUIDs. `applySessionCookies` attaches them as cookies in the HTTP response:
the session token as an HttpOnly cookie (invisible to JavaScript, safe from XSS), and
the CSRF token as a readable cookie (so the browser can include it in future request
headers to prove the request came from our own page).

---

## Summary Diagram

```
LOGIN ATTEMPT
    │
    ▼
[Rate limiter] ──── over 5/IP/15min ────► 429 Too Many Requests
    │ under limit
    ▼
[DB lookup for email]
    │
    ├── not found ──► bcrypt dummy compare (constant time) ──► 401 (generic)
    │
    ▼
[Lockout check: lockedUntil > now?]
    │
    ├── yes ──► 423 Locked
    │
    ▼
[bcrypt.compare(password, hash)]
    │
    ├── no match ──► increment failedAttempts
    │                  ├── if >= 10: write lockedUntil = now + 1h
    │                  └── return 401 (generic)
    │
    └── match ──► reset failedAttempts=0, lockedUntil=null
                   └── create session ──► 200 + cookies

─────────────────────────────────────────────

RESET REQUEST
    │
    ▼
[Rate limiter] ──── over 3/IP/1h ────► 200 generic (no leak)
    │ under limit
    ▼
[DB lookup for email]
    │
    ├── not found ──► 200 generic (same message, no leak)
    │
    └── found ──► invalidate old tokens
                   └── generate rawToken (UUID)
                        └── store bcrypt(rawToken) + expiresAt in DB
                             └── console.log rawToken ──► 200 generic

─────────────────────────────────────────────

RESET CONFIRM
    │
    ▼
[Validate new password strength]
    │ fails ──► 400 with specific rule message
    │
    ▼
[Load all unused, unexpired reset rows]
    │
    └── loop: bcrypt.compare(rawToken, row.tokenHash)
         │
         ├── no match found ──► 400 "invalid or expired"
         │
         └── match found ──► $transaction {
                                mark token used,
                                write new passwordHash,
                                reset failedAttempts + lockedUntil,
                                delete ALL sessions
                              }
                              └── create fresh session ──► 200 + cookies
```
