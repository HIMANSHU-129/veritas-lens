import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { getServerEnv } from "./env";
import { sanitizeText, validatePublicTargetUrl } from "./security";

if (typeof window !== "undefined") {
  throw new Error("scanner.ts must only be imported on the server");
}

export interface PhishingSignal {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
}

export interface SecurityHeaderAudit {
  name: string;
  key: string;
  present: boolean;
  value: string | null;
  recommendation: string;
}

export interface RedirectHop {
  url: string;
  status: number;
}

export interface ScanReport {
  scannedAt: string;
  targetUrl: string;
  finalUrl: string;
  hostname: string;
  score: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  verdict: "Safe" | "Caution" | "High Risk";
  phishing: {
    riskLevel: "Low" | "Elevated" | "Critical";
    detected: boolean;
    signals: PhishingSignal[];
    externalFeeds: {
      virusTotal: string;
      googleSafeBrowsing: string;
    };
  };
  ssl: {
    enabled: boolean;
    authorized: boolean;
    protocol: string | null;
    cipher: string | null;
    issuer: string | null;
    subject: string | null;
    validFrom: string | null;
    validTo: string | null;
    daysRemaining: number | null;
    error: string | null;
  };
  http: {
    statusCode: number | null;
    latencyMs: number;
    redirectChain: RedirectHop[];
    server: string | null;
    poweredBy: string | null;
    securityHeaders: SecurityHeaderAudit[];
  };
  dns: {
    resolvedIps: string[];
    ipv4: string[];
    ipv6: string[];
    mx: string[];
    ns: string[];
    hasSpf: boolean;
    hasDmarc: boolean;
    cdnOrWaf: string | null;
  };
  intelligence: {
    title: string | null;
    description: string | null;
    ogTitle: string | null;
    canonical: string | null;
    techStack: string[];
    trackers: string[];
    hasPasswordForm: boolean;
    externalLinkCount: number;
  };
  scoreBreakdown: { label: string; delta: number }[];
}

const SUSPICIOUS_TLDS = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "xyz",
  "top",
  "click",
  "zip",
  "mov",
  "icu",
  "work",
  "loan",
  "rest",
]);

const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "ow.ly",
  "buff.ly",
]);

const PROTECTED_BRANDS: { brand: string; officialDomains: string[] }[] = [
  { brand: "paypal", officialDomains: ["paypal.com", "paypal.me"] },
  { brand: "google", officialDomains: ["google.com", "googleapis.com", "accounts.google.com"] },
  { brand: "microsoft", officialDomains: ["microsoft.com", "live.com", "office.com", "outlook.com"] },
  { brand: "apple", officialDomains: ["apple.com", "icloud.com"] },
  { brand: "amazon", officialDomains: ["amazon.com", "amazon.in", "aws.amazon.com"] },
  { brand: "netflix", officialDomains: ["netflix.com"] },
  { brand: "facebook", officialDomains: ["facebook.com", "fb.com", "meta.com"] },
  { brand: "instagram", officialDomains: ["instagram.com"] },
  { brand: "whatsapp", officialDomains: ["whatsapp.com"] },
  { brand: "binance", officialDomains: ["binance.com"] },
  { brand: "coinbase", officialDomains: ["coinbase.com"] },
  { brand: "metamask", officialDomains: ["metamask.io"] },
  { brand: "chase", officialDomains: ["chase.com"] },
  { brand: "github", officialDomains: ["github.com"] },
];

const PHISHING_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "verification",
  "secure",
  "update",
  "wallet",
  "banking",
  "confirm",
  "suspend",
  "unlock",
  "password",
  "otp",
];

function getRegistrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

function normalizeHomoglyphs(input: string): string {
  return input
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a");
}

function detectPhishingSignals(
  url: URL,
  hasPasswordForm: boolean
): PhishingSignal[] {
  const signals: PhishingSignal[] = [];
  const hostname = url.hostname.toLowerCase();
  const registrable = getRegistrableDomain(hostname);
  const labels = hostname.split(".");
  const tld = labels[labels.length - 1] ?? "";

  if (url.protocol !== "https:") {
    signals.push({
      id: "no-https",
      severity: "high",
      title: "Unencrypted HTTP Connection",
      detail: "Site does not enforce HTTPS encryption.",
    });
  }

  if (hostname.includes("xn--")) {
    signals.push({
      id: "idn-punycode",
      severity: "high",
      title: "IDN Punycode Domain",
      detail: "Domain uses punycode encoding, which can mask homograph lookalikes.",
    });
  }

  if (net.isIP(hostname)) {
    signals.push({
      id: "ip-literal",
      severity: "high",
      title: "Raw IP Address Host",
      detail: "Legitimate services rarely serve user pages on a bare IP address.",
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    signals.push({
      id: "suspicious-tld",
      severity: "medium",
      title: `High-Abuse TLD (.${tld})`,
      detail: `The .${tld} top-level domain has elevated phishing abuse rates.`,
    });
  }

  if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(registrable)) {
    signals.push({
      id: "url-shortener",
      severity: "medium",
      title: "URL Shortener Detected",
      detail: "Shortened links obscure the final destination.",
    });
  }

  if (labels.length > 4) {
    signals.push({
      id: "deep-subdomains",
      severity: "medium",
      title: "Excessive Subdomain Nesting",
      detail: `Hostname has ${labels.length} domain labels, often used to mimic trusted domains.`,
    });
  }

  // Brand impersonation check
  const normalizedHost = normalizeHomoglyphs(hostname);
  for (const entry of PROTECTED_BRANDS) {
    const isOfficial = entry.officialDomains.some(
      (d) => hostname === d || hostname.endsWith(`.${d}`)
    );
    if (!isOfficial && normalizedHost.includes(entry.brand)) {
      signals.push({
        id: `brand-impersonation-${entry.brand}`,
        severity: "critical",
        title: `Possible ${entry.brand.toUpperCase()} Impersonation`,
        detail: `Hostname references "${entry.brand}" but is not an official ${entry.brand} domain.`,
      });
    }
  }

  const pathAndQuery = `${url.pathname}${url.search}`.toLowerCase();
  const matchedKeywords = PHISHING_KEYWORDS.filter((kw) =>
    pathAndQuery.includes(kw)
  );
  if (matchedKeywords.length >= 2) {
    signals.push({
      id: "phishing-keywords",
      severity: "medium",
      title: "Credential-Harvesting URL Keywords",
      detail: `URL path/query contains sensitive keywords: ${matchedKeywords.slice(0, 4).join(", ")}.`,
    });
  }

  if (hasPasswordForm && signals.some((s) => s.severity === "high" || s.severity === "critical")) {
    signals.push({
      id: "password-form-risk",
      severity: "critical",
      title: "Password Input on Flagged Domain",
      detail: "Page collects credentials while exhibiting high-risk domain signals.",
    });
  }

  return signals;
}

async function inspectTls(hostname: string, port = 443): Promise<ScanReport["ssl"]> {
  return new Promise((resolve) => {
    const isIp = net.isIP(hostname) !== 0;
    const socket = tls.connect(
      {
        host: hostname,
        port,
        ...(isIp ? {} : { servername: hostname }),
        rejectUnauthorized: false,
        timeout: 6000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() ?? null;
          const cipherInfo = socket.getCipher();
          const authorized = socket.authorized;

          const validFrom = cert?.valid_from ? new Date(cert.valid_from).toISOString() : null;
          const validTo = cert?.valid_to ? new Date(cert.valid_to).toISOString() : null;
          const daysRemaining = validTo
            ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86_400_000)
            : null;

          const issuer =
            cert?.issuer?.O || cert?.issuer?.CN || null;
          const subject = cert?.subject?.CN || null;

          socket.end();
          resolve({
            enabled: true,
            authorized,
            protocol,
            cipher: cipherInfo?.name ?? null,
            issuer: issuer ? sanitizeText(String(issuer), 120) : null,
            subject: subject ? sanitizeText(String(subject), 120) : null,
            validFrom,
            validTo,
            daysRemaining,
            error: authorized ? null : String(socket.authorizationError || "Untrusted certificate"),
          });
        } catch {
          socket.destroy();
          resolve({
            enabled: false,
            authorized: false,
            protocol: null,
            cipher: null,
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            error: "Failed to parse TLS certificate",
          });
        }
      }
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        enabled: false,
        authorized: false,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        error: "TLS handshake timed out",
      });
    });

    socket.on("error", (err) => {
      socket.destroy();
      resolve({
        enabled: false,
        authorized: false,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        error: sanitizeText(err.message, 120),
      });
    });
  });
}

async function inspectDns(hostname: string, resolvedIps: string[], headers: Headers) {
  const registrable = getRegistrableDomain(hostname);

  const [ipv4Res, ipv6Res, mxRes, nsRes, txtRes, dmarcRes] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveMx(registrable),
    dns.resolveNs(registrable),
    dns.resolveTxt(registrable),
    dns.resolveTxt(`_dmarc.${registrable}`),
  ]);

  const ipv4 = ipv4Res.status === "fulfilled" ? ipv4Res.value.slice(0, 6) : [];
  const ipv6 = ipv6Res.status === "fulfilled" ? ipv6Res.value.slice(0, 4) : [];
  const mx =
    mxRes.status === "fulfilled"
      ? mxRes.value.sort((a, b) => a.priority - b.priority).map((m) => m.exchange).slice(0, 5)
      : [];
  const ns = nsRes.status === "fulfilled" ? nsRes.value.slice(0, 5) : [];

  const txtFlat =
    txtRes.status === "fulfilled" ? txtRes.value.map((chunks) => chunks.join("")) : [];
  const hasSpf = txtFlat.some((t) => t.toLowerCase().includes("v=spf1"));

  const dmarcFlat =
    dmarcRes.status === "fulfilled" ? dmarcRes.value.map((chunks) => chunks.join("")) : [];
  const hasDmarc = dmarcFlat.some((t) => t.toLowerCase().includes("v=dmarc1"));

  // Detect CDN / WAF from headers or nameservers
  let cdnOrWaf: string | null = null;
  const server = (headers.get("server") || "").toLowerCase();
  const nsJoined = ns.join(" ").toLowerCase();
  if (server.includes("cloudflare") || headers.has("cf-ray") || nsJoined.includes("cloudflare")) {
    cdnOrWaf = "Cloudflare";
  } else if (headers.has("x-amz-cf-id") || server.includes("cloudfront")) {
    cdnOrWaf = "AWS CloudFront";
  } else if (server.includes("vercel") || headers.has("x-vercel-id")) {
    cdnOrWaf = "Vercel Edge";
  } else if (server.includes("netlify") || headers.has("x-nf-request-id")) {
    cdnOrWaf = "Netlify Edge";
  } else if (server.includes("akamai") || headers.has("x-akamai-transformed")) {
    cdnOrWaf = "Akamai";
  } else if (headers.has("x-served-by") && headers.get("x-served-by")?.includes("cache-")) {
    cdnOrWaf = "Fastly";
  }

  return {
    resolvedIps: resolvedIps.slice(0, 6),
    ipv4,
    ipv6,
    mx,
    ns,
    hasSpf,
    hasDmarc,
    cdnOrWaf,
  };
}

function decodeBasicEntities(input: string): string {
  return input
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, " ")
    .replace(/&middot;/gi, "·")
    .replace(/&ndash;/gi, "–")
    .replace(/&mdash;/gi, "—");
}

function extractHtmlIntelligence(html: string, headers: Headers, baseHost: string) {
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? sanitizeText(decodeBasicEntities(titleMatch[1]), 160) : null;

  const descMatch =
    html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) ||
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i);
  const description = descMatch ? sanitizeText(decodeBasicEntities(descMatch[1]), 240) : null;

  const ogTitleMatch =
    html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i) ||
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:title["']/i);
  const ogTitle = ogTitleMatch ? sanitizeText(decodeBasicEntities(ogTitleMatch[1]), 160) : null;

  const canonicalMatch = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i);
  const canonical = canonicalMatch ? sanitizeText(canonicalMatch[1], 300) : null;

  const techStack = new Set<string>();
  const serverHeader = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  if (serverHeader) techStack.add(sanitizeText(serverHeader.split("/")[0], 40));
  if (poweredBy) techStack.add(sanitizeText(poweredBy, 40));

  if (html.includes("__NEXT_DATA__") || html.includes("/_next/")) techStack.add("Next.js");
  if (html.includes("data-reactroot") || html.includes("react")) techStack.add("React");
  if (html.includes("__NUXT__")) techStack.add("Nuxt");
  if (html.includes("wp-content") || html.includes("wp-includes")) techStack.add("WordPress");
  if (html.includes("cdn.shopify.com")) techStack.add("Shopify");
  if (html.includes("tailwindcss") || /class=["'][^"']*\b(flex|grid|bg-|text-)\b/.test(html)) {
    techStack.add("Tailwind / Utility CSS");
  }
  if (html.includes("bootstrap")) techStack.add("Bootstrap");

  const trackers = new Set<string>();
  const lowerHtml = html.toLowerCase();
  if (lowerHtml.includes("googletagmanager.com") || lowerHtml.includes("google-analytics.com")) {
    trackers.add("Google Analytics / GTM");
  }
  if (lowerHtml.includes("connect.facebook.net") || lowerHtml.includes("fbq(")) {
    trackers.add("Meta Pixel");
  }
  if (lowerHtml.includes("hotjar.com")) trackers.add("Hotjar");
  if (lowerHtml.includes("clarity.ms")) trackers.add("Microsoft Clarity");
  if (lowerHtml.includes("cdn.segment.com")) trackers.add("Segment");
  if (lowerHtml.includes("mixpanel.com")) trackers.add("Mixpanel");
  if (lowerHtml.includes("analytics.tiktok.com")) trackers.add("TikTok Pixel");

  const hasPasswordForm = /<input[^>]+type=["']password["']/i.test(html);

  const linkMatches = html.match(/href=["']https?:\/\/([^"'/]+)/gi) ?? [];
  let externalLinkCount = 0;
  for (const m of linkMatches) {
    const rawHost = m.replace(/^href=["']https?:\/\//i, "").toLowerCase();
    const hostOnly = rawHost.split(":")[0];
    if (hostOnly && hostOnly !== baseHost && !hostOnly.endsWith(`.${baseHost}`)) {
      externalLinkCount += 1;
    }
  }

  return {
    title,
    description,
    ogTitle,
    canonical,
    techStack: Array.from(techStack).slice(0, 10),
    trackers: Array.from(trackers).slice(0, 10),
    hasPasswordForm,
    externalLinkCount,
  };
}

async function checkExternalThreatFeeds(targetUrl: string): Promise<{
  virusTotal: string;
  googleSafeBrowsing: string;
  flagged: boolean;
}> {
  const env = getServerEnv();
  let virusTotal = "Not configured (optional API key)";
  let googleSafeBrowsing = "Not configured (optional API key)";
  let flagged = false;

  if (env.VIRUSTOTAL_API_KEY) {
    try {
      const urlId = Buffer.from(targetUrl).toString("base64url");
      const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { "x-apikey": env.VIRUSTOTAL_API_KEY },
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = (await res.json()) as {
          data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number } } };
        };
        const stats = data.data?.attributes?.last_analysis_stats;
        const malicious = stats?.malicious ?? 0;
        const suspicious = stats?.suspicious ?? 0;
        if (malicious > 0 || suspicious > 0) {
          flagged = true;
          virusTotal = `Flagged (${malicious} malicious, ${suspicious} suspicious)`;
        } else {
          virusTotal = "Clean (0 detections)";
        }
      } else {
        virusTotal = `Unavailable (HTTP ${res.status})`;
      }
    } catch {
      virusTotal = "Lookup timed out";
    }
  }

  if (env.GOOGLE_SAFE_BROWSING_KEY) {
    try {
      const res = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(
          env.GOOGLE_SAFE_BROWSING_KEY
        )}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "aegis-sentinel", clientVersion: "1.0.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: targetUrl }],
            },
          }),
          signal: AbortSignal.timeout(5000),
        }
      );
      if (res.ok) {
        const data = (await res.json()) as { matches?: { threatType?: string }[] };
        if (data.matches && data.matches.length > 0) {
          flagged = true;
          googleSafeBrowsing = `Flagged (${data.matches.map((m) => m.threatType).join(", ")})`;
        } else {
          googleSafeBrowsing = "Clean (no threats matched)";
        }
      } else {
        googleSafeBrowsing = `Unavailable (HTTP ${res.status})`;
      }
    } catch {
      googleSafeBrowsing = "Lookup timed out";
    }
  }

  return { virusTotal, googleSafeBrowsing, flagged };
}

export async function scanWebsite(rawInput: string): Promise<ScanReport> {
  const initialTarget = await validatePublicTargetUrl(rawInput);
  const redirectChain: RedirectHop[] = [];
  let currentUrl = initialTarget.url;
  let currentIps = initialTarget.resolvedIps;

  const startedAt = Date.now();
  let finalResponse: Response | null = null;

  for (let hop = 0; hop < 6; hop += 1) {
    const res = await fetch(currentUrl.toString(), {
      method: "GET",
      redirect: "manual",
      headers: {
        "User-Agent": "AegisSentinel-Scanner/1.0 (+https://localhost)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: AbortSignal.timeout(8000),
    });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      redirectChain.push({ url: currentUrl.toString(), status: res.status });
      if (!location) {
        finalResponse = res;
        break;
      }
      const nextRaw = new URL(location, currentUrl).toString();
      const validatedNext = await validatePublicTargetUrl(nextRaw);
      currentUrl = validatedNext.url;
      currentIps = validatedNext.resolvedIps;
      continue;
    }

    finalResponse = res;
    break;
  }

  const latencyMs = Date.now() - startedAt;
  const headers = finalResponse?.headers ?? new Headers();
  const statusCode = finalResponse?.status ?? null;

  let html = "";
  if (finalResponse) {
    const contentType = headers.get("content-type") || "";
    if (contentType.includes("text/html") || contentType.includes("application/xhtml")) {
      const buf = await finalResponse.arrayBuffer();
      const slice = buf.slice(0, 512 * 1024);
      html = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    } else {
      await finalResponse.body?.cancel();
    }
  }

  const rawFinalHost = currentUrl.hostname.toLowerCase();
  const finalHostname =
    rawFinalHost.startsWith("[") && rawFinalHost.endsWith("]")
      ? rawFinalHost.slice(1, -1)
      : rawFinalHost;
  const tlsPort = currentUrl.port ? Number(currentUrl.port) : 443;

  const [ssl, dnsInfo, externalFeeds] = await Promise.all([
    currentUrl.protocol === "https:"
      ? inspectTls(finalHostname, tlsPort)
      : Promise.resolve<ScanReport["ssl"]>({
          enabled: false,
          authorized: false,
          protocol: null,
          cipher: null,
          issuer: null,
          subject: null,
          validFrom: null,
          validTo: null,
          daysRemaining: null,
          error: "HTTPS not used",
        }),
    inspectDns(finalHostname, currentIps, headers),
    checkExternalThreatFeeds(currentUrl.toString()),
  ]);

  const intelligence = extractHtmlIntelligence(html, headers, getRegistrableDomain(finalHostname));
  const phishingSignals = detectPhishingSignals(currentUrl, intelligence.hasPasswordForm);

  if (externalFeeds.flagged) {
    phishingSignals.unshift({
      id: "external-threat-feed",
      severity: "critical",
      title: "Flagged by External Threat Intelligence",
      detail: "One or more external threat feeds reported this URL as malicious or phishing.",
    });
  }

  const headerSpecs: { name: string; key: string; recommendation: string }[] = [
    {
      name: "Strict-Transport-Security (HSTS)",
      key: "strict-transport-security",
      recommendation: "Enforces HTTPS and prevents SSL-stripping attacks.",
    },
    {
      name: "Content-Security-Policy (CSP)",
      key: "content-security-policy",
      recommendation: "Restricts script/resource origins to mitigate XSS.",
    },
    {
      name: "X-Frame-Options",
      key: "x-frame-options",
      recommendation: "Prevents clickjacking via unauthorized iframe embedding.",
    },
    {
      name: "X-Content-Type-Options",
      key: "x-content-type-options",
      recommendation: "Stops browsers from MIME-sniffing responses.",
    },
    {
      name: "Referrer-Policy",
      key: "referrer-policy",
      recommendation: "Controls how much referrer URL data leaks on navigation.",
    },
    {
      name: "Permissions-Policy",
      key: "permissions-policy",
      recommendation: "Locks down camera, mic, and geolocation browser APIs.",
    },
  ];

  const securityHeaders: SecurityHeaderAudit[] = headerSpecs.map((spec) => {
    const val = headers.get(spec.key);
    return {
      name: spec.name,
      key: spec.key,
      present: Boolean(val),
      value: val ? sanitizeText(val, 180) : null,
      recommendation: spec.recommendation,
    };
  });

  // Deterministic score calculation
  let score = 100;
  const scoreBreakdown: { label: string; delta: number }[] = [];

  if (currentUrl.protocol !== "https:") {
    score -= 30;
    scoreBreakdown.push({ label: "No HTTPS encryption", delta: -30 });
  } else if (!ssl.enabled || !ssl.authorized) {
    score -= 25;
    scoreBreakdown.push({ label: "Invalid or untrusted TLS certificate", delta: -25 });
  } else if (ssl.daysRemaining !== null && ssl.daysRemaining < 14) {
    score -= 10;
    scoreBreakdown.push({ label: "SSL certificate expiring within 14 days", delta: -10 });
  }

  const missingHeaders = securityHeaders.filter((h) => !h.present).length;
  if (missingHeaders > 0) {
    const penalty = Math.min(24, missingHeaders * 4);
    score -= penalty;
    scoreBreakdown.push({
      label: `${missingHeaders} recommended HTTP security header(s) missing`,
      delta: -penalty,
    });
  }

  if (!dnsInfo.hasSpf && !dnsInfo.hasDmarc) {
    score -= 6;
    scoreBreakdown.push({ label: "Missing SPF & DMARC email spoofing records", delta: -6 });
  }

  for (const sig of phishingSignals) {
    const penalty =
      sig.severity === "critical"
        ? 35
        : sig.severity === "high"
          ? 20
          : sig.severity === "medium"
            ? 10
            : 0;
    if (penalty > 0) {
      score -= penalty;
      scoreBreakdown.push({ label: sig.title, delta: -penalty });
    }
  }

  score = Math.max(0, Math.min(100, score));

  const grade: ScanReport["grade"] =
    score >= 95
      ? "A+"
      : score >= 85
        ? "A"
        : score >= 70
          ? "B"
          : score >= 55
            ? "C"
            : score >= 35
              ? "D"
              : "F";

  const hasCritical = phishingSignals.some((s) => s.severity === "critical");
  const verdict: ScanReport["verdict"] =
    hasCritical || score < 50 ? "High Risk" : score < 80 ? "Caution" : "Safe";

  const riskLevel: ScanReport["phishing"]["riskLevel"] =
    hasCritical || phishingSignals.filter((s) => s.severity === "high").length >= 2
      ? "Critical"
      : phishingSignals.length > 0
        ? "Elevated"
        : "Low";

  return {
    scannedAt: new Date().toISOString(),
    targetUrl: initialTarget.url.toString(),
    finalUrl: currentUrl.toString(),
    hostname: finalHostname,
    score,
    grade,
    verdict,
    phishing: {
      riskLevel,
      detected: riskLevel !== "Low",
      signals: phishingSignals,
      externalFeeds: {
        virusTotal: externalFeeds.virusTotal,
        googleSafeBrowsing: externalFeeds.googleSafeBrowsing,
      },
    },
    ssl,
    http: {
      statusCode,
      latencyMs,
      redirectChain,
      server: headers.get("server") ? sanitizeText(headers.get("server")!, 80) : null,
      poweredBy: headers.get("x-powered-by")
        ? sanitizeText(headers.get("x-powered-by")!, 80)
        : null,
      securityHeaders,
    },
    dns: dnsInfo,
    intelligence,
    scoreBreakdown,
  };
}
