import { z } from "zod";

if (typeof window !== "undefined") {
  throw new Error("env.ts must only be imported on the server");
}

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  VIRUSTOTAL_API_KEY: z.string().optional().default(""),
  GOOGLE_SAFE_BROWSING_KEY: z.string().optional().default(""),
});

let cachedEnv: z.infer<typeof envSchema> | null = null;

export function getServerEnv() {
  if (cachedEnv) return cachedEnv;
  const parsed = envSchema.safeParse({
    NODE_ENV: process.env.NODE_ENV,
    VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
    GOOGLE_SAFE_BROWSING_KEY: process.env.GOOGLE_SAFE_BROWSING_KEY,
  });

  if (!parsed.success) {
    throw new Error("Invalid server environment configuration");
  }

  cachedEnv = parsed.data;
  return cachedEnv;
}
