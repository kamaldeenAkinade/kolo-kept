import { NextRequest, NextResponse } from "next/server";

const PUBLIC_PAGES = [
  "/login",
  "/signup",
  "/reset-password",
];

const PUBLIC_API = [
  "/api/auth/login",
  "/api/auth/signup",
  "/api/auth/reset-password/request",
  "/api/auth/reset-password/confirm",
];

// Middleware runs in the Edge Runtime — no Node.js APIs or Prisma.
// It performs a lightweight cookie-presence check for routing.
// Full session validation (DB lookup + expiry) happens in each route handler
// and in server component layouts via lib/auth.ts getSession().
export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.includes(".")
  ) {
    return NextResponse.next();
  }

  const isPublicPage = PUBLIC_PAGES.some(
    (p) => pathname === p || pathname.startsWith(p + "/")
  );
  const isPublicApi = PUBLIC_API.some((p) => pathname.startsWith(p));

  if (isPublicApi) return NextResponse.next();

  const hasSessionCookie = !!request.cookies.get("session")?.value;

  if (!hasSessionCookie) {
    if (isPublicPage) return NextResponse.next();
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Not authenticated." }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/login", request.url));
  }

  if (isPublicPage) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
