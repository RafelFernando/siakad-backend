import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { JwtPayload } from "../types/auth";

export const verifyToken = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            res.sendStatus(401);
            return;
        }

        const token = authHeader.split(" ")[1];

        if (!token) {
            res.sendStatus(401);
            return;
        }

        const decoded = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET as string
        ) as JwtPayload;

        req.user = decoded;

        next();

    } catch (error) {
        console.error("Verify Token Error:", error);

        res.sendStatus(403);
    }
};