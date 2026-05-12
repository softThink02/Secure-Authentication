import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { jwtVerify } from "jose";

const secret = new TextEncoder().encode(process.env.JWT_SECRET as string);

export async function middleware(req: NextRequest) {
  const token = req.cookies.get("refreshToken")?.value;
  const url = req.nextUrl.clone();

  const isDashboardRoute = url.pathname.startsWith("/dashboard");
  const isAuthRoute =
    url.pathname === "/login" || url.pathname === "/register";

  const isValidToken = async () => {
    if (!token) return false;
    try {
      await jwtVerify(token, secret);
      return true;
    } catch {
      return false;
    }
  };

  const authenticated = await isValidToken();

  if (!authenticated && isDashboardRoute) {
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }

  if (authenticated && isAuthRoute) {
    url.pathname = "/dashboard";
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/login", "/register"],
};