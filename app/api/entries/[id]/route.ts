import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getSession, validateCsrf } from "@/lib/auth";

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  if (!(await validateCsrf(request))) {
    return NextResponse.json({ error: "Invalid request." }, { status: 403 });
  }

  const session = await getSession(request);
  if (!session) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  const { id } = await params;

  const entry = await prisma.entry.findUnique({
    where: { id },
    select: { userId: true },
  });

  if (!entry || entry.userId !== session.userId) {
    return NextResponse.json({ error: "Entry not found." }, { status: 404 });
  }

  await prisma.entry.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}
