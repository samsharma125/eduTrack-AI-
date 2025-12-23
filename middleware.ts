import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import * as jose from "jose"; 

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET!);

export async function middleware(req: NextRequest) {
  const token = req.cookies.get("token")?.value;
  const { pathname } = req.nextUrl;

  const isPublicPath = pathname === "/login" || pathname === "/register";

  // 1. Redirect to dashboard if already logged in and hitting login page
  if (isPublicPath && token) {
    try {
      const { payload } = await jose.jwtVerify(token, JWT_SECRET);
      const role = payload.role as string;
      return NextResponse.redirect(new URL(role === "teacher" ? "/teacher/dashboard" : "/dashboard", req.url));
    } catch (e) {
       // Invalid token, allow them to stay on login
    }
  }

  // 2. Redirect to login if NO token and trying to access protected paths
  if (!token && !isPublicPath) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  try {
    if (token && !isPublicPath) {
      const { payload } = await jose.jwtVerify(token, JWT_SECRET);
      const role = payload.role as string;

      // Role Protection
      if (pathname.startsWith("/teacher") && role !== "teacher") {
        return NextResponse.redirect(new URL("/dashboard", req.url));
      }
    }
    return NextResponse.next();
  } catch (err) {
    const response = NextResponse.redirect(new URL("/login", req.url));
    response.cookies.delete("token");
    return response;
  }
}

export const config = {
  // Ignore static assets and API routes
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};