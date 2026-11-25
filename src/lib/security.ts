import dns from "node:dns/promises";
import net from "node:net";
import { NextRequest } from "next/server";

if (typeof window !== "undefined") {
  throw new Error("security.ts must only be imported on the server");
}

export function getClientIp(req: NextRequest): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first && net.isIP(first)) return first;
  }
  const realIp = req.headers.get("x-real-ip")?.trim();
  if (realIp && net.isIP(realIp)) return realIp;
  return "127.0.0.1";
}

export function sanitizeText(input: string, maxLen = 300): string {
  return input
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen);
}

/**
 * Checks whether an IPv4 or IPv6 address belongs to a private, loopback,
 * link-local, multicast, or otherwise reserved range (SSRF protection).
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  if (normalized.startsWith("::ffff:")) {
    return isPrivateOrReservedIp(normalized.slice(7));
  }

  if (net.isIPv4(normalized)) {
    const parts = normalized.split(".").map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
    const [a, b] = parts;

    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
    if (a === 192 && b === 0 && parts[2] === 2) return true; // TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
    if (a >= 224) return true; // multicast & reserved
    return false;
  }

  if (net.isIPv6(normalized)) {
    if (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fe80:") || // link-local
      normalized.startsWith("fc") || // ULA
      normalized.startsWith("fd") || // ULA
      normalized.startsWith("ff") // multicast
    ) {
      return true;
    }
    return false;
  }

  return true;
}

export interface ValidatedTarget {
  url: URL;
  resolvedIps: string[];
}

/**
 * Validates and normalizes a user-supplied URL and verifies via DNS that it
 * does not resolve to a private/internal IP address (prevents SSRF).
 */
export async function validatePublicTargetUrl(
  rawInput: string
): Promise<ValidatedTarget> {
  const trimmed = rawInput.trim();
  if (!trimmed || trimmed.length > 2048) {
    throw new Error("URL must be between 1 and 2048 characters.");
  }

  const withProtocol = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(withProtocol);
  } catch {
    throw new Error("Invalid URL format.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS protocols are permitted.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are not permitted.");
  }

  const rawHostname = parsed.hostname.toLowerCase();
  const hostname =
    rawHostname.startsWith("[") && rawHostname.endsWith("]")
      ? rawHostname.slice(1, -1)
      : rawHostname;

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error("Internal or local hostnames are blocked.");
  }

  // If hostname is an IP literal, check directly
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new Error("Private or reserved IP addresses are blocked.");
    }
    return { url: parsed, resolvedIps: [hostname] };
  }

  // Resolve DNS records and reject any private/reserved target IP
  let records: { address: string; family: number }[];
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error(`Could not resolve hostname: ${hostname}`);
  }

  if (!records.length) {
    throw new Error(`No DNS records found for ${hostname}`);
  }

  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error("Target resolves to a private or restricted IP range.");
    }
  }

  return {
    url: parsed,
    resolvedIps: records.map((r) => r.address),
  };
}
