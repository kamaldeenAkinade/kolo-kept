import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { validatePasswordStrength } from "@/lib/password";
import { createSession, applySessionCookies } from "@/lib/auth";

export async function POST(request: NextRequest) {
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

    // Find all unused, unexpired reset records and check against the raw token.
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
