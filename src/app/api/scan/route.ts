import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { checkRateLimit } from "@/lib/rate-limit";
import { scanWebsite } from "@/lib/scanner";
import { getClientIp } from "@/lib/security";

const scanSchema = z.object({
  url: z.string().trim().min(1, "Please enter a website URL").max(2048),
});

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rl = checkRateLimit(`scan:${ip}`, 15, 60_000);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait before scanning again." },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSeconds) } }
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON payload" }, { status: 400 });
  }

  const parsed = scanSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message || "Invalid URL input" },
      { status: 400 }
    );
  }

  try {
    const report = await scanWebsite(parsed.data.url);
    return NextResponse.json({ report });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to analyze target website";
    const isClientError =
      message.includes("URL") ||
      message.includes("protocol") ||
      message.includes("blocked") ||
      message.includes("resolve") ||
      message.includes("private");

    return NextResponse.json(
      { error: isClientError ? message : "Unable to reach or inspect target website." },
      { status: isClientError ? 400 : 502 }
    );
  }
}
