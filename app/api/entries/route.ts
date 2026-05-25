import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getSession, validateCsrf } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const session = await getSession(request);
  if (!session) {
    return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
  }

  const entries = await prisma.entry.findMany({
    where: { userId: session.userId },
    orderBy: { date: "desc" },
  });

  return NextResponse.json({ entries });
}

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
    const { amount, note, date } = body as {
      amount?: number;
      note?: string;
      date?: string;
    };

    if (amount == null || !note || !date) {
      return NextResponse.json(
        { error: "Amount, note, and date are required." },
        { status: 400 }
      );
    }

    const parsedAmount = Number(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return NextResponse.json(
        { error: "Amount must be a positive number." },
        { status: 400 }
      );
    }

    const parsedDate = new Date(date);
    if (isNaN(parsedDate.getTime())) {
      return NextResponse.json(
        { error: "Invalid date format." },
        { status: 400 }
      );
    }

    const entry = await prisma.entry.create({
      data: {
        userId: session.userId,
        amount: parsedAmount,
        note: note.trim().slice(0, 500),
        date: parsedDate,
      },
    });

    return NextResponse.json({ entry }, { status: 201 });
  } catch {
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
}
