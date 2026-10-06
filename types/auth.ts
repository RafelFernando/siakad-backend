import { Role } from "../generated/prisma/client";

export interface JwtPayload {
    userId: string;
    name: string;
    email: string;
    role: Role;
}