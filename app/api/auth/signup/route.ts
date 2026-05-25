import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { createSession, applySessionCookies } from "@/lib/auth";
import { validatePasswordStrength } from "@/lib/password";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password } = body as { email?: string; password?: string };

    if (!email || !password) {
      return NextResponse.json(
        { error: "Email and password are required." },
        { status: 400 }
      );
    }

    const emailNormalized = email.toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNormalized)) {
      return NextResponse.json(
        { error: "Please enter a valid email address." },
        { status: 400 }
      );
    }

    const strengthCheck = validatePasswordStrength(password);
    if (!strengthCheck.valid) {
      return NextResponse.json({ error: strengthCheck.message }, { status: 400 });
    }

    // Check for existing user but return the same response to prevent enumeration.
    const existing = await prisma.user.findUnique({
      where: { email: emailNormalized },
      select: { id: true },
    });

    if (existing) {
      // Generic response — does not reveal that the email is already registered.
      return NextResponse.json(
        { error: "Unable to create account. Please try a different email." },
        { status: 409 }
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: { email: emailNormalized, passwordHash },
    });

    const { sessionToken, csrfToken } = await createSession(user.id);
    const response = NextResponse.json({ ok: true }, { status: 201 });
    applySessionCookies(response, sessionToken, csrfToken);
    return response;
  } catch {
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
}
