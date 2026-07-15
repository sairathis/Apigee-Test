import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "apigee-sim-local-dev-secret-change-me";
const JWT_EXPIRY = "12h";

export interface JwtPayload {
  id: string;
  email: string;
  role: string;
  name: string;
}

export function signToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

export function verifyToken(token: string): JwtPayload {
  return jwt.verify(token, JWT_SECRET) as JwtPayload;
}
