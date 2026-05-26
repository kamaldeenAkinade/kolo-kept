import { createHash } from "crypto";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "./prisma";

const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const SESSION_DURATION_SECONDS = 7 * 24 * 60 * 60;

export async function createSession(userId: string): Promise<{
  sessionToken: string;
  csrfToken: string;
}> {
  const sessionToken = crypto.randomUUID();
  const csrfToken = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

  // Store a SHA-256 hash so database read access can't forge live sessions.
  const tokenHash = createHash("sha256").update(sessionToken).digest("hex");
  await prisma.session.create({
    data: { userId, token: tokenHash, csrfToken, expiresAt },
  });

  return { sessionToken, csrfToken };
}

export function applySessionCookies(
  response: NextResponse,
  sessionToken: string,
  csrfToken: string
): void {
  const isProd = process.env.NODE_ENV === "production";

  response.cookies.set("session", sessionToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    maxAge: SESSION_DURATION_SECONDS,
    path: "/",
  });

  // Not httpOnly so client JS can read it for the double-submit CSRF pattern.
  response.cookies.set("csrf-token", csrfToken, {
    httpOnly: false,
    secure: isProd,
    sameSite: "lax",
    maxAge: SESSION_DURATION_SECONDS,
    path: "/",
  });
}

export function clearSessionCookies(response: NextResponse): void {
  response.cookies.set("session", "", { maxAge: 0, path: "/" });
  response.cookies.set("csrf-token", "", { maxAge: 0, path: "/" });
}

export async function getSession(request?: NextRequest) {
  let token: string | undefined;

  if (request) {
    token = request.cookies.get("session")?.value;
  } else {
    const cookieStore = await cookies();
    token = cookieStore.get("session")?.value;
  }

  if (!token) return null;

  const tokenHash = createHash("sha256").update(token).digest("hex");
  const session = await prisma.session.findUnique({
    where: { token: tokenHash },
    include: { user: true },
  });

  if (!session) return null;
  if (session.expiresAt < new Date()) {
    await prisma.session.delete({ where: { id: session.id } });
    return null;
  }

  return session;
}

export async function requireSession(request?: NextRequest) {
  const session = await getSession(request);
  if (!session) return null;
  return session;
}

export function getClientIp(request: NextRequest): string {
  // Next.js 15 removed `ip` from the type but it still exists at runtime on
  // Vercel (set from the TCP connection, not client headers). Fall back to
  // x-forwarded-for only as a secondary option for other environments.
  const reqWithIp = request as NextRequest & { ip?: string };
  return (
    reqWithIp.ip ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "127.0.0.1"
  );
}

export async function validateCsrf(
  request: NextRequest
): Promise<boolean> {
  const headerToken = request.headers.get("x-csrf-token");
  if (!headerToken) return false;

  const sessionToken = request.cookies.get("session")?.value;
  if (!sessionToken) return false;

  const tokenHash = createHash("sha256").update(sessionToken).digest("hex");
  const session = await prisma.session.findUnique({
    where: { token: tokenHash },
    select: { csrfToken: true, expiresAt: true },
  });

  if (!session || session.expiresAt < new Date()) return false;
  return session.csrfToken === headerToken;
}
