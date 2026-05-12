import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";
import argon2 from "argon2";
import { SignJWT } from "jose";


const ACCESS_EXPIRES = "15m";
const REFRESH_EXPIRES_SECONDS = 7 * 24 * 60 * 60;

export async function POST(req: NextRequest) {
    try {
        const { email, password } = await req.json();

        if (!email || !password) {
            return NextResponse.json({ error: "Email and password are required" }, { status: 400 });
        }


        // find user
        const user = await prisma.user.findUnique({ where: { email:email.toLowerCase() } });
        if (!user) {
            return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        }

        // verify password
        const isPasswordValid = await argon2.verify(user.password, password);
        if (!isPasswordValid) {
            return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        }


        // ساخت JWT
        const secret = new TextEncoder().encode(process.env.JWT_SECRET as string);
        const accessToken = await new SignJWT({ userId: user.id })
            .setProtectedHeader({ alg: "HS256" })
            .setExpirationTime(ACCESS_EXPIRES)
            .sign(secret);


        await prisma.refreshToken.deleteMany({ where: { userId: user.id } });



        const refreshToken = await new SignJWT({ userId: user.id })
            .setProtectedHeader({ alg: "HS256" })
            .setExpirationTime("7d")
            .sign(secret);

        // save refresh token in DB
        await prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId: user.id,
                expiresAt: new Date(Date.now() + REFRESH_EXPIRES_SECONDS * 1000),
            },
        });

        
       // response with cookie
    const res = NextResponse.json({
      message: "Login successful",
      accessToken,
    });

    res.cookies.set("refreshToken", refreshToken, {
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
