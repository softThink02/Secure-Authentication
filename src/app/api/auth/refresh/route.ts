import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";
import { jwtVerify, SignJWT } from "jose";

const ACCESS_EXPIRES = "15m";
const REFRESH_EXPIRES_SECONDS = 7 * 24 * 60 * 60; // 7 روز
const secret = new TextEncoder().encode(process.env.JWT_SECRET as string);

export async function POST(req: NextRequest) {
  try {
    const cookie = req.cookies.get("refreshToken")?.value;
    if (!cookie)
      return NextResponse.json({ error: "No refresh token" }, { status: 401 });

    const dbToken = await prisma.refreshToken.findFirst({ where: { token: cookie } });
    if (!dbToken)
      return NextResponse.json({ error: "Invalid refresh token" }, { status: 401 });

    try {
      await jwtVerify(cookie, secret);
    } catch (e) {
      await prisma.refreshToken.deleteMany({ where: { token: cookie } }).catch(() => {});
      return NextResponse.json({ error: "Invalid refresh token" }, { status: 401 });
    }

    const { payload } = await jwtVerify(cookie, secret);
    const userId = (payload as any).userId as string;

    // حذف توکن قدیمی و ساخت جدید
    await prisma.refreshToken.deleteMany({ where: { token: cookie } });

    const newAccessToken = await new SignJWT({ userId })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime(ACCESS_EXPIRES)
      .sign(secret);

    const newRefreshToken = await new SignJWT({ userId })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("7d")
      .sign(secret);

    await prisma.refreshToken.create({
      data: {
        token: newRefreshToken,
        userId,
        expiresAt: new Date(Date.now() + REFRESH_EXPIRES_SECONDS * 1000),
      },
    });

    // ست کردن کوکی با روش Next.js
    const res = NextResponse.json({ accessToken: newAccessToken });
    res.cookies.set("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: REFRESH_EXPIRES_SECONDS,
    });

    return res;
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : "Something went wrong"
    return NextResponse.json({ error: errMessage }, { status: 500 });
  }
}
