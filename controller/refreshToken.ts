import { Request, Response } from "express";
import jwt, { VerifyErrors } from "jsonwebtoken";
import { prisma } from "../lib/prisma";

export const RefreshToken = async (
    req: Request,
    res: Response
): Promise<Response> => {
    try {
        // 1. Ambil refresh token dari cookie
        const refreshToken = req.cookies.refreshToken;

        console.log("Refresh token from cookie:", refreshToken);

        // 2. Kalau cookie tidak ada
        if (!refreshToken) {
            console.log("No refresh token found in cookies");
            return res.sendStatus(401);
        }

        // 3. Cari user berdasarkan refresh token
        const user = await prisma.user.findFirst({
            where: {
                refreshToken: refreshToken,
            },
        });

        console.log("User found:", !!user);

        // 4. Kalau user tidak ditemukan
        if (!user) {
            console.log("No user found with this refresh token");
            return res.sendStatus(403);
        }

        // 5. Verifikasi refresh token
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET as string,
            (err: VerifyErrors | null) => {
                if (err) {
                    console.log(
                        "Token verification failed:",
                        err.message
                    );

                    return res.sendStatus(403);
                }

                // 6. Buat access token baru
                const accessToken = jwt.sign(
                    {
                        userId: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role,
                    },
                    process.env.ACCESS_TOKEN_SECRET as string,
                    {
                        expiresIn: "30s",
                    }
                );

                console.log(
                    "New access token generated for user:",
                    user.email
                );

                // 7. Kirim access token baru
                return res.json({
                    accessToken,
                });
            }
        );

        return res.sendStatus(403);
    } catch (error) {
        console.error("RefreshToken error:", error);

        return res.sendStatus(500);
    }
};