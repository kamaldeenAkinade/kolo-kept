import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { getSession, validateCsrf, createSession, applySessionCookies } from "@/lib/auth";
import { validatePasswordStrength } from "@/lib/password";

export async function POST(request: NextRequest) {
  if (!(await validateCsrf(request))) {
    return NextResponse.json({ error: "Invalid request." }, { status: 403 });
  }

  const session = await getSession(request);
  if (!session) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { currentPassword, newPassword } = body as {
      currentPassword?: string;
      newPassword?: string;
    };

    if (!currentPassword || !newPassword) {
      return NextResponse.json(
        { error: "Current and new passwords are required." },
        { status: 400 }
      );
    }

    const strengthCheck = validatePasswordStrength(newPassword);
    if (!strengthCheck.valid) {
      return NextResponse.json({ error: strengthCheck.message }, { status: 400 });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { passwordHash: true },
    });

    if (!user) {
      return NextResponse.json(
        { error: "Something went wrong. Please log in again." },
        { status: 404 }
      );
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!passwordMatch) {
      return NextResponse.json(
        { error: "Current password is incorrect." },
        { status: 400 }
      );
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // Update password and invalidate all sessions in one transaction.
    // Existing sessions (including any attacker's) are invalidated so that
    // changing a compromised password actually locks the attacker out.
    await prisma.$transaction([
      prisma.user.update({
        where: { id: session.userId },
        data: { passwordHash: newPasswordHash },
      }),
      prisma.session.deleteMany({ where: { userId: session.userId } }),
    ]);

    // Issue a fresh session for the current user.
    const { sessionToken, csrfToken } = await createSession(session.userId);
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
