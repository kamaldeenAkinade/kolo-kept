import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/auth";
import bcrypt from "bcryptjs";

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
// Throttle reset requests to 3 per IP per hour.
const RESET_RATE_LIMIT = 3;
const RESET_WINDOW_MS = 60 * 60 * 1000;

// Generic response used regardless of whether the email exists.
const GENERIC_RESPONSE = {
  message:
    "If that email is registered, you will receive reset instructions shortly.",
};

export async function POST(request: NextRequest) {
  const ip = getClientIp(request);
  const rateCheck = checkRateLimit(
    `reset:${ip}`,
    RESET_RATE_LIMIT,
    RESET_WINDOW_MS
  );
  if (!rateCheck.allowed) {
    // Still return 200 to prevent enumeration via timing.
    return NextResponse.json(GENERIC_RESPONSE);
  }

  try {
    const body = await request.json();
    const { email } = body as { email?: string };

    if (!email) return NextResponse.json(GENERIC_RESPONSE);

    const emailNormalized = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email: emailNormalized },
      select: { id: true },
    });

    if (!user) {
      // Return generic response to prevent email enumeration.
      return NextResponse.json(GENERIC_RESPONSE);
    }

    // Invalidate any existing reset tokens for this user.
    await prisma.passwordReset.updateMany({
      where: { userId: user.id, used: false },
      data: { used: true },
    });

    const rawToken = crypto.randomUUID();
    const tokenHash = await bcrypt.hash(rawToken, 10);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    await prisma.passwordReset.create({
      data: { userId: user.id, tokenHash, expiresAt },
    });

    // In production, send this via Resend or similar. For the prototype, log it.
    console.log(
      `\n[PASSWORD RESET TOKEN] Email: ${emailNormalized} | Token: ${rawToken}\n` +
        `Reset URL: http://localhost:3000/reset-password/confirm?token=${rawToken}\n`
    );

    return NextResponse.json(GENERIC_RESPONSE);
  } catch {
    return NextResponse.json(GENERIC_RESPONSE);
  }
}
