import crypto from "crypto";

// Generates Apigee-style consumer key/secret pairs for developer apps.
export function generateConsumerKey(): string {
  return crypto.randomBytes(24).toString("hex");
}

export function generateConsumerSecret(): string {
  return crypto.randomBytes(18).toString("hex");
}

export function generateId(prefix = ""): string {
  const id = crypto.randomBytes(8).toString("hex");
  return prefix ? `${prefix}-${id}` : id;
}
