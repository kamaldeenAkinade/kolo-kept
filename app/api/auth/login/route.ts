import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { createSession, applySessionCookies, getClientIp } from "@/lib/auth";
import { checkRateLimit } from "@/lib/rate-limit";

const LOGIN_RATE_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const LOCKOUT_THRESHOLD = 10;
const LOCKOUT_DURATION_MS = 60 * 60 * 1000; // 1 hour

// Generic credential error — never reveals whether the email exists.
const INVALID_CREDENTIALS = "Invalid email or password.";

export async function POST(request: NextRequest) {
  const ip = getClientIp(request);
  const rateLimitKey = `login:${ip}`;

  const rateCheck = checkRateLimit(rateLimitKey, LOGIN_RATE_LIMIT, LOGIN_WINDOW_MS);
  if (!rateCheck.allowed) {
    const retryAfterSecs = Math.ceil(rateCheck.retryAfterMs / 1000);
    return NextResponse.json(
      { error: "Too many login attempts. Please try again later." },
      {
        status: 429,
        headers: { "Retry-After": String(retryAfterSecs) },
      }
    );
  }

  try {
    const body = await request.json();
    const { email, password } = body as { email?: string; password?: string };

    if (!email || !password) {
      return NextResponse.json({ error: INVALID_CREDENTIALS }, { status: 401 });
    }

    const emailNormalized = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email: emailNormalized },
    });

    // Run bcrypt even when user doesn't exist to prevent timing attacks.
    const dummyHash =
      "$2a$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const hashToCompare = user?.passwordHash ?? dummyHash;

    if (!user) {
      await bcrypt.compare(password, hashToCompare);
      return NextResponse.json({ error: INVALID_CREDENTIALS }, { status: 401 });
    }

    // Run bcrypt BEFORE the lockout check so a locked account takes the same
    // time as a wrong-password attempt — prevents a timing oracle that would
    // confirm the email is registered.
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    // Lockout check AFTER bcrypt (timing equalized above). Return the same
    // INVALID_CREDENTIALS message so the lockout state doesn't confirm that
    // the email is registered.
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return NextResponse.json({ error: INVALID_CREDENTIALS }, { status: 401 });
    }

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

    // Successful login — reset failure counters.
    await prisma.user.update({
      where: { id: user.id },
      data: { failedAttempts: 0, lockedUntil: null },
    });

    const { sessionToken, csrfToken } = await createSession(user.id);
    const response = NextResponse.json({ ok: true });
    applySessionCookies(response, sessionToken, csrfToken);
    return response;
  } catch {
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
}
