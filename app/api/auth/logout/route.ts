import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { clearSessionCookies, validateCsrf } from "@/lib/auth";

export async function POST(request: NextRequest) {
  if (!(await validateCsrf(request))) {
    return NextResponse.json({ error: "Invalid request." }, { status: 403 });
  }

  const sessionToken = request.cookies.get("session")?.value;
  if (sessionToken) {
    await prisma.session.deleteMany({ where: { token: sessionToken } });
  }

  const response = NextResponse.json({ ok: true });
  clearSessionCookies(response);
  return response;
}
