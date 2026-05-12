import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const cookie = req.cookies.get("refreshToken")?.value;

    if (cookie) {
      await prisma.refreshToken.deleteMany({ where: { token: cookie } }).catch(() => {});
    }

    const res = NextResponse.json({ message: "Logged out" });
    res.cookies.set("refreshToken", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });

    return res;
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : "Something went wrong"
    return NextResponse.json({ error: errMessage }, { status: 500 });
  }
}
