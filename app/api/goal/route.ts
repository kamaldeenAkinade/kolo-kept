import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getSession, validateCsrf } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await getSession(request);
  if (!session) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  const user = await prisma.user.findUnique({
    where: { id: session.userId },
    select: { savingsGoal: true },
  });

  return NextResponse.json({ savingsGoal: user?.savingsGoal ?? null });
}

export async function PUT(request: NextRequest) {
  if (!(await validateCsrf(request))) {
    return NextResponse.json({ error: "Invalid request." }, { status: 403 });
  }

  const session = await getSession(request);
  if (!session) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { savingsGoal } = body as { savingsGoal?: number | null };

    const parsed = savingsGoal == null ? null : Number(savingsGoal);
    if (parsed !== null && (isNaN(parsed) || parsed <= 0)) {
      return NextResponse.json(
        { error: "Savings goal must be a positive number." },
        { status: 400 }
      );
    }

    await prisma.user.update({
      where: { id: session.userId },
      data: { savingsGoal: parsed },
    });

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
}
