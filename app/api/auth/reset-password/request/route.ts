import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/auth";

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
const RESET_RATE_LIMIT = 3;
const RESET_WINDOW_MS = 60 * 60 * 1000;

// Generic response used regardless of whether the email exists.
const GENERIC_RESPONSE = {
  message:
    "If that email is registered, you will receive reset instructions shortly.",
};

export async function POST(request: NextRequest) {
  const ip = getClientIp(request);
  const rateCheck = checkRateLimit(`reset:${ip}`, RESET_RATE_LIMIT, RESET_WINDOW_MS);
  if (!rateCheck.allowed) {
    return NextResponse.json(GENERIC_RESPONSE);
  }

  try {
    const body = await request.json();
    const { email } = body as { email?: string };

    if (!email) return NextResponse.json(GENERIC_RESPONSE);

    const emailNormalized = email.toLowerCase().trim();

    // Per-email rate limit prevents an attacker from repeatedly invalidating a
    // victim's token and flooding them with emails.
    const emailRateCheck = checkRateLimit(
      `reset-email:${emailNormalized}`,
      RESET_RATE_LIMIT,
      RESET_WINDOW_MS
    );
    if (!emailRateCheck.allowed) {
      return NextResponse.json(GENERIC_RESPONSE);
    }

    const user = await prisma.user.findUnique({
      where: { email: emailNormalized },
      select: { id: true },
    });

    if (!user) {
      // No timing equalization needed: switching to SHA-256 (below) eliminates
      // the large bcrypt gap that made the "user not found" path measurably
      // faster than the "user found" path.
      return NextResponse.json(GENERIC_RESPONSE);
    }

    // Invalidate any existing reset tokens for this user.
    await prisma.passwordReset.updateMany({
      where: { userId: user.id, used: false },
      data: { used: true },
    });

    const rawToken = crypto.randomUUID();
    // SHA-256 instead of bcrypt: O(1) indexed lookup in the confirm step
    // (eliminates the O(n)×bcrypt DoS amplifier). 122-bit entropy still makes
    // brute-force computationally impossible even with a fast hash.
    const tokenHash = createHash("sha256").update(rawToken).digest("hex");
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    const newReset = await prisma.passwordReset.create({
      data: { userId: user.id, tokenHash, expiresAt },
    });

    // In production replace this with a real email send (e.g. Resend/SendGrid).
    // Never log the raw token outside of development — it is a usable credential.
    try {
      if (process.env.NODE_ENV === "development") {
        const resetUrl = `http://localhost:3000/reset-password/confirm?token=${rawToken}`;
        console.log(`[PASSWORD RESET] Request for ${emailNormalized} — ${resetUrl}`);
      }
      // TODO: await sendResetEmail(emailNormalized, rawToken);
    } catch (emailError) {
      console.error("[PASSWORD RESET] Email send failed:", emailError);
      // Invalidate the token so the database stays clean when no email arrived.
      await prisma.passwordReset.update({
        where: { id: newReset.id },
        data: { used: true },
      });
      return NextResponse.json(
        { message: "We could not send the email. Please try again in a moment." },
        { status: 503 }
      );
    }

    return NextResponse.json(GENERIC_RESPONSE);
  } catch {
    return NextResponse.json(GENERIC_RESPONSE);
  }
}
