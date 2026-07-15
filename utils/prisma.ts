import { PrismaClient } from "@prisma/client";

// Single shared Prisma Client instance for the whole backend process.
export const prisma = new PrismaClient({
  log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
});

export default prisma;
