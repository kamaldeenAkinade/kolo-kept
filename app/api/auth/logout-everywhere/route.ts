import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { clearSessionCookies, getSession, validateCsrf } from "@/lib/auth";

export async function POST(request: NextRequest) {
  if (!(await validateCsrf(request))) {
    return NextResponse.json({ error: "Invalid request." }, { status: 403 });
  }

  const session = await getSession(request);
  if (!session) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  // Delete all sessions for this user.
  await prisma.session.deleteMany({ where: { userId: session.userId } });

  const response = NextResponse.json({ ok: true });
  clearSessionCookies(response);
  return response;
}
