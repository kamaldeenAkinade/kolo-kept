import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { validatePasswordStrength } from "@/lib/password";
import { createSession, applySessionCookies, getClientIp } from "@/lib/auth";
import { checkRateLimit } from "@/lib/rate-limit";

const CONFIRM_RATE_LIMIT = 5;
const CONFIRM_WINDOW_MS = 15 * 60 * 1000;

export async function POST(request: NextRequest) {
  const ip = getClientIp(request);
  const rateCheck = checkRateLimit(`reset-confirm:${ip}`, CONFIRM_RATE_LIMIT, CONFIRM_WINDOW_MS);
  if (!rateCheck.allowed) {
    return NextResponse.json(
      { error: "This reset link is invalid or has expired." },
      { status: 400 }
    );
  }

  try {
    const body = await request.json();
    const { token, password } = body as { token?: string; password?: string };

    if (!token || !password) {
      return NextResponse.json(
        { error: "Token and new password are required." },
        { status: 400 }
      );
    }

    const strengthCheck = validatePasswordStrength(password);
    if (!strengthCheck.valid) {
      return NextResponse.json({ error: strengthCheck.message }, { status: 400 });
    }

    // SHA-256 hash for O(1) indexed lookup — replaces the O(n)×bcrypt linear
    // scan that could be used as a DoS amplifier.
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const matchedReset = await prisma.passwordReset.findFirst({
      where: { tokenHash, used: false, expiresAt: { gt: new Date() } },
      include: { user: true },
    });

    if (!matchedReset) {
      return NextResponse.json(
        { error: "This reset link is invalid or has expired." },
        { status: 400 }
      );
    }

    const newPasswordHash = await bcrypt.hash(password, 12);

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
      // Invalidate all sessions so stolen sessions can't persist.
      prisma.session.deleteMany({ where: { userId: matchedReset.userId } }),
    ]);

    // Log the user in immediately after reset.
    const { sessionToken, csrfToken } = await createSession(matchedReset.userId);
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
