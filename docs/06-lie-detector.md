# Lie Detector — Auth Hardening Edition

Five statements about how the security fixes actually work in the code.
Four are exactly true. One is wrong in a specific, provable way.

Read the statements, open the files, find the lie, prove it with a line
number. Then scroll past the rule to check the AI's answer.

---

## The Five Statements

**A.**
When a signup request arrives for an email that is already registered,
`signup/route.ts` calls `bcrypt.hash("dummy-equalize-timing", 12)` before
returning the 409 response. This deliberately adds ~300 ms of latency so both
code paths — existing email and new email — take roughly the same wall-clock
time to respond, removing any timing signal an attacker could use to enumerate
registered addresses.

---

**B.**
`lib/auth.ts` never writes the raw session token to the database.
`createSession` generates the token, immediately computes
`createHash("sha256").update(sessionToken).digest("hex")`, and stores only
the hash in the `token` column of the Session table. Both `getSession` and
`validateCsrf` hash the incoming cookie value before running their
`prisma.session.findUnique` queries — the plaintext token exists only in the
HTTP cookie and in process memory during the request.

---

**C.**
The reset-password confirm endpoint retrieves the submitted token with a call
to `prisma.passwordReset.findUnique({ where: { tokenHash } })`, exploiting the
`@unique` index on `tokenHash` for a guaranteed single-row O(1) lookup. This
replaced the former loop that called `bcrypt.compare` against every active
token — the DoS amplifier that let an attacker exhaust the event loop by
generating a large number of active tokens and then flooding the confirm
endpoint.

---

**D.**
When a user changes their password, `change-password/route.ts` executes
`prisma.$transaction([user.update(...), session.deleteMany(...)])` — the
password hash update and the deletion of all existing sessions happen
atomically in a single database transaction. After the transaction commits,
`createSession(session.userId)` issues a fresh token and the new cookies are
sent back to the caller.

---

**E.**
The `console.log` in `reset-password/request/route.ts` that previously printed
the raw reset token (and the full reset URL) to stdout on every request is now
inside `if (process.env.NODE_ENV === "development")`. In any non-development
environment — including Vercel production and preview deployments, where
`NODE_ENV` is `"production"` — that block is never reached, so the token never
appears in Vercel function logs, CloudWatch, or any other aggregator with
broader access than the application database.

---
## My Answer
C - I checked the code for all the other options and I confirmed they are correct.
---

## AI's Answer

**The lie is Statement C.**

The claim: `prisma.passwordReset.findUnique({ where: { tokenHash } })`

The reality: the call on
`app/api/auth/reset-password/confirm/route.ts` line 41 is

```typescript
const matchedReset = await prisma.passwordReset.findFirst({
  where: { tokenHash, used: false, expiresAt: { gt: new Date() } },
  include: { user: true },
});
```

**Why `findFirst` and not `findUnique`?**

Prisma's `findUnique` only accepts a `where` argument whose shape exactly
matches the unique constraint — no extra conditions. Adding `used: false` and
`expiresAt: { gt: new Date() }` alongside `tokenHash` is not valid for
`findUnique`; the TypeScript types reject it. `findFirst` allows arbitrary
additional conditions while still hitting the index on `tokenHash`, so the
query is still O(1) — the Prisma method name is different, the performance
characteristic is the same.

Statements A, B, D, and E are accurate to the line.
