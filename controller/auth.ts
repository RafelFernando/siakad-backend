import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma";

export const getUsers = async (
    req: Request,
    res: Response
): Promise<Response> => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
            },
        });

        return res.json(users);
    } catch (error) {
        console.error("Get Users Error:", error);

        return res.status(500).json({
            msg: "Gagal mengambil data user",
        });
    }
};

export const Register = async (
    req: Request,
    res: Response
): Promise<Response> => {
    try {
        const {
            name,
            email,
            password,
            confPassword,
        } = req.body;

        // Cek input
        if (!name || !email || !password || !confPassword) {
            return res.status(400).json({
                msg: "Semua field wajib diisi",
            });
        }

        // Cek password
        if (password !== confPassword) {
            return res.status(400).json({
                msg: "Password dan Confirm Password tidak sesuai",
            });
        }

        // Cek apakah email sudah terdaftar
        const existingUser = await prisma.user.findUnique({
            where: {
                email: email,
            },
        });

        if (existingUser) {
            return res.status(409).json({
                msg: "Email sudah terdaftar",
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt();
        const hashPassword = await bcrypt.hash(
            password,
            salt
        );

        // Simpan user
        await prisma.user.create({
            data: {
                name: name,
                email: email,
                password: hashPassword,
            },
        });

        return res.status(201).json({
            msg: "Register Berhasil",
        });

    } catch (error) {
        console.error("Register Error:", error);

        return res.status(500).json({
            msg: "Terjadi kesalahan pada server",
        });
    }
};

export const Login = async (
    req: Request,
    res: Response
): Promise<Response> => {
    try {
        const {
            email,
            password,
        } = req.body;

        // Cari user berdasarkan email
        const user = await prisma.user.findUnique({
            where: {
                email: email,
            },
        });

        // User tidak ditemukan
        if (!user) {
            return res.status(404).json({
                msg: "User tidak ditemukan",
            });
        }

        // Cek password
        const match = await bcrypt.compare(
            password,
            user.password
        );

        if (!match) {
            return res.status(400).json({
                msg: "Password Salah",
            });
        }

        const accessToken = jwt.sign(
            {
                userId: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
            },
            process.env.ACCESS_TOKEN_SECRET as string,
            {
                expiresIn: "20s",
            }
        );

        const refreshToken = jwt.sign(
            {
                userId: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
            },
            process.env.REFRESH_TOKEN_SECRET as string,
            {
                expiresIn: "1d",
            }
        );

        // Simpan refresh token ke database
        await prisma.user.update({
            where: {
                id: user.id,
            },
            data: {
                refreshToken: refreshToken,
            },
        });

        // Simpan refresh token di HTTP Only Cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
        });

        // Kirim access token ke frontend
        return res.json({
            accessToken,
        });

    } catch (error) {
        console.error("Login Error:", error);

        return res.status(500).json({
            msg: "Terjadi kesalahan pada server",
        });
    }
};

export const Logout = async (
    req: Request,
    res: Response
): Promise<Response> => {
    try {
        // Ambil refresh token dari cookie
        const refreshToken = req.cookies.refreshToken;

        // Tidak ada refresh token
        if (!refreshToken) {
            return res.sendStatus(204);
        }

        // Cari user berdasarkan refresh token
        const user = await prisma.user.findFirst({
            where: {
                refreshToken: refreshToken,
            },
        });

        // User tidak ditemukan
        if (!user) {
            return res.sendStatus(204);
        }

        // Hapus refresh token dari database
        await prisma.user.update({
            where: {
                id: user.id,
            },
            data: {
                refreshToken: null,
            },
        });

        // Hapus cookie
        res.clearCookie("refreshToken");

        return res.sendStatus(200);

    } catch (error) {
        console.error("Logout Error:", error);

        return res.status(500).json({
            msg: "Gagal logout",
        });
    }
};