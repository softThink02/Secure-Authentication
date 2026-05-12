import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";
import argon2 from "argon2";

export async function POST(req: NextRequest) {

    try {
        let { email, password, name } = await req.json();
        if (!email || !password) {
            return NextResponse.json({ error: "Email and password are required" }, { status: 400 });
        }

        email = email.toLowerCase();

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return NextResponse.json({ error: "Email already registered" }, { status: 400 });
        }

        const hashedPassword = await argon2.hash(password)

        const user = await prisma.user.create({
            data: {
                email,
                name,
                password: hashedPassword
            }
        });

        return NextResponse.json({ message: "User created successfully", user: { id: user.id, email: user.email } });

    } catch (err) {
        const errMessage = err instanceof Error ? err.message : "Something went wrong"
        return NextResponse.json({ error:  errMessage as string}, { status: 500 });
    }


}
