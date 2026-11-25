"use client";

import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Compass,
  Cpu,
  Download,
  ExternalLink,
  Eye,
  Globe,
  History,
  Lock,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Waypoints,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { ScanReport } from "@/lib/scanner";
import { InteractiveField } from "./InteractiveField";
import { SecurityGauge } from "./SecurityGauge";

const STORAGE_KEY = "veritas_lens_recent_scans_v1";

const SCAN_STAGES = [
  "01 // SSRF GUARD & DNS RESOLUTION",
  "02 // TLS / SSL CERTIFICATE HANDSHAKE",
  "03 // PHISHING & IMPERSONATION HEURISTICS",
  "04 // HTTP HEADERS & TECH STACK AUDIT",
];

const ANATOMY_SEGMENTS = [
  {
    id: "proto",
    label: "http://",
    risk: "High Risk",
    title: "Unencrypted Transport",
    explanation:
      "Missing HTTPS means traffic can be intercepted or tampered with on public networks. Legitimate login portals enforce TLS.",
    deduction: "-30 pts",
  },
  {
    id: "sub",
    label: "secure-login.",
    risk: "Elevated",
    title: "Deceptive Subdomain",
    explanation:
      "Attackers prepend trusted words like 'secure-' or 'account-' as subdomains to create false confidence before the real domain.",
    deduction: "Heuristic Flag",
  },
  {
    id: "brand",
    label: "paypa1",
    risk: "Critical",
    title: "Homoglyph / Brand Spoofing",
    explanation:
      "Replacing 'l' with '1' (or 'o' with '0') mimics a well-known brand. Our normalizer catches lookalike brand impersonation.",
    deduction: "-35 pts",
  },
  {
    id: "tld",
    label: ".tk",
    risk: "Medium",
    title: "High-Abuse Top-Level Domain",
    explanation:
      "Free or low-cost TLDs (.tk, .ml, .xyz, .click) have disproportionately high phishing abuse rates.",
    deduction: "-10 pts",
  },
  {
    id: "path",
    label: "/verify?otp=1",
    risk: "Medium",
    title: "Credential-Harvesting Keywords",
    explanation:
      "Multiple sensitive path tokens ('verify', 'otp', 'login', 'wallet') paired with a password form trigger critical phishing alerts.",
    deduction: "-10 pts",
  },
];

const CAPABILITIES = [
  {
    id: "phishing",
    title: "Phishing & Brand Spoofing",
    icon: ShieldAlert,
    summary:
      "Detects homoglyph lookalikes (e.g. paypa1 vs paypal), IDN punycode, raw IP URLs, suspicious TLDs, URL shorteners, and credential-harvesting forms.",
    checks: [
      "Homoglyph & brand-impersonation normalizer",
      "IDN punycode (xn--) inspection",
      "Password form detection on flagged hosts",
      "Optional VirusTotal & Google Safe Browsing feeds",
    ],
  },
  {
    id: "tls",
    title: "TLS / SSL Cryptography",
    icon: Lock,
    summary:
      "Opens a direct TLS socket on port 443 to inspect the live peer certificate chain, cipher suite, and expiration window.",
    checks: [
      "TLSv1.3 / TLSv1.2 protocol verification",
      "Certificate authority & subject CN check",
      "Days-until-expiry countdown",
      "Untrusted or self-signed cert flagging",
    ],
  },
  {
    id: "headers",
    title: "HTTP Security Headers",
    icon: ShieldCheck,
    summary:
      "Audits six critical browser defense headers that protect visitors from XSS, clickjacking, MIME-sniffing, and protocol downgrades.",
    checks: [
      "Strict-Transport-Security (HSTS)",
      "Content-Security-Policy (CSP)",
      "X-Frame-Options & X-Content-Type-Options",
      "Referrer-Policy & Permissions-Policy",
    ],
  },
  {
    id: "dns",
    title: "DNS, SPF & DMARC",
    icon: Server,
    summary:
      "Queries live DNS records to map server IPs, mail exchangers, nameservers, CDN/WAF providers, and email anti-spoofing policies.",
    checks: [
      "IPv4, IPv6, MX & NS resolution",
      "SPF (v=spf1) anti-spoofing check",
      "DMARC (_dmarc) policy verification",
      "Cloudflare, CloudFront, Vercel & Akamai detection",
    ],
  },
  {
    id: "redirects",
    title: "Redirect & SSRF Guard",
    icon: Waypoints,
    summary:
      "Follows redirect chains hop-by-hop while blocking private, loopback, and cloud-metadata IP ranges at every single hop.",
    checks: [
      "Up to 5 redirect hops traced with status codes",
      "Private IPv4/IPv6 & localhost blocking",
      "DNS rebinding / SSRF protection",
      "Total response latency measurement",
    ],
  },
  {
    id: "stack",
    title: "Tech Stack & Trackers",
    icon: Cpu,
    summary:
      "Safely parses HTML metadata without executing scripts to reveal frameworks, third-party analytics trackers, and outbound links.",
    checks: [
      "Page title, description & canonical URL",
      "Next.js, React, WordPress, Shopify & server stack",
      "Google Analytics, Meta Pixel, Hotjar & Clarity",
      "External link count & password input audit",
    ],
  },
];

export function ScannerWorkspace() {
  const [urlInput, setUrlInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);

  const [history, setHistory] = useState<ScanReport[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  const [activeSegment, setActiveSegment] = useState(ANATOMY_SEGMENTS[2]);
  const [activeCap, setActiveCap] = useState(CAPABILITIES[0]);

  useEffect(() => {
    let active = true;
    Promise.resolve().then(() => {
      if (!active) return;
      try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw) as ScanReport[];
          if (Array.isArray(parsed)) {
            setHistory(parsed.slice(0, 12));
          }
        }
      } catch {
        // Ignore malformed localStorage
      }
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!scanning) return;
    const timer = setInterval(() => {
      setStageIndex((prev) => (prev + 1) % SCAN_STAGES.length);
    }, 650);
    return () => clearInterval(timer);
  }, [scanning]);

  function saveToLocalHistory(newReport: ScanReport) {
    setHistory((prev) => {
      const filtered = prev.filter((item) => item.finalUrl !== newReport.finalUrl);
      const next = [newReport, ...filtered].slice(0, 12);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore storage quota errors
      }
      return next;
    });
  }

  function clearLocalHistory() {
    setHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignore
    }
  }

  async function runScan(targetOverride?: string) {
    const target = (targetOverride ?? urlInput).trim();
    if (!target) {
      setError("Enter a website URL or domain to analyze.");
      return;
    }

    setError(null);
    setScanning(true);
    setStageIndex(0);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });

      const data = (await res.json()) as { report?: ScanReport; error?: string };
      if (!res.ok || !data.report) {
        setError(data.error || "Scan failed.");
        return;
      }

      setReport(data.report);
      saveToLocalHistory(data.report);
    } catch {
      setError("Network error while scanning target.");
    } finally {
      setScanning(false);
    }
  }

  function handleExportJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `veritas-report-${report.hostname}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="relative min-h-screen flex flex-col">
      <InteractiveField />

      {/* Top Navigation */}
      <header className="sticky top-0 z-30 border-b border-stone-200/10 bg-[#0b0c0a]/85 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3.5 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-amber-500/35 bg-amber-500/10 text-amber-300">
              <Compass className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display text-base font-bold tracking-wide text-stone-100">
                  VERITAS <span className="text-amber-400">LENS</span>
                </span>
                <span className="hidden items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-950/60 px-2 py-0.5 font-mono text-[10px] text-emerald-300 sm:inline-flex">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  INDEPENDENT · NO LOGIN
                </span>
              </div>
              <p className="font-mono text-[10px] tracking-wider text-stone-400">
                REAL-TIME WEBSITE SECURITY &amp; PHISHING INTELLIGENCE
              </p>
            </div>
          </div>

          <nav className="flex items-center gap-2 sm:gap-3">
            <a
              href="#phishing-lab"
              className="hidden rounded-lg px-2.5 py-1.5 font-mono text-xs text-stone-300 transition hover:text-amber-300 md:inline-block"
            >
              Phishing Lab
            </a>
            <a
              href="#capabilities"
              className="hidden rounded-lg px-2.5 py-1.5 font-mono text-xs text-stone-300 transition hover:text-amber-300 md:inline-block"
            >
              Capabilities
            </a>
            <button
              type="button"
              onClick={() => setShowHistory((s) => !s)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-stone-700/80 bg-stone-900/70 px-3 py-1.5 font-mono text-xs text-stone-200 transition hover:border-amber-500/50"
            >
              <History className="h-3.5 w-3.5 text-amber-400" />
              <span>RECENT</span> ({history.length})
            </button>
          </nav>
        </div>
      </header>

      <main className="relative z-10 mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6">
        {/* Hero Scanner Console */}
        <section className="surface-card rounded-2xl p-6 sm:p-9">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 font-mono text-[11px] uppercase tracking-widest text-amber-300">
              <Sparkles className="h-3.5 w-3.5" />
              Zero-Database · On-Demand Inspection
            </div>
            <span className="font-mono text-[11px] text-stone-400">
              LIVE TLS · DNS · HEADERS · PHISHING HEURISTICS
            </span>
          </div>

          <h1 className="font-display text-3xl font-bold tracking-tight text-stone-100 sm:text-4xl lg:text-5xl">
            Know what&apos;s behind any link{" "}
            <span className="text-amber-400">before you trust it.</span>
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-relaxed text-stone-300 sm:text-base">
            Paste any website URL to immediately inspect its security rating, detect phishing or
            brand impersonation, verify SSL/TLS certificates, audit HTTP security headers, trace
            redirects, and uncover its tech stack—with zero sign-up required.
          </p>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void runScan();
            }}
            className="mt-6 flex flex-col gap-3 sm:flex-row"
          >
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-amber-400/80" />
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com or domain.tld"
                aria-label="Website URL to scan"
                className="w-full rounded-xl border border-stone-700/80 bg-[#0b0c0a]/90 py-3.5 pl-10 pr-4 font-mono text-sm text-stone-100 placeholder:text-stone-500 outline-none transition focus:border-amber-400 focus:ring-2 focus:ring-amber-500/20"
              />
            </div>
            <button
              type="submit"
              disabled={scanning}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-amber-500 px-6 py-3.5 font-mono text-xs font-semibold uppercase tracking-[0.16em] text-stone-950 shadow-[0_0_25px_rgba(217,155,67,0.25)] transition hover:bg-amber-400 disabled:opacity-60"
            >
              <Eye className={`h-4 w-4 ${scanning ? "animate-pulse" : ""}`} />
              {scanning ? "Inspecting..." : "Inspect Target"}
            </button>
          </form>

          <div className="mt-3.5 flex flex-wrap items-center gap-2 text-xs text-stone-400">
            <span className="font-mono text-[11px] uppercase tracking-wider text-stone-500">
              Try Live Examples:
            </span>
            {[
              "https://github.com",
              "https://example.com",
              "https://cloudflare.com",
              "https://wikipedia.org",
            ].map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => {
                  setUrlInput(sample);
                  void runScan(sample);
                }}
                className="rounded-md border border-stone-800 bg-stone-900/70 px-2.5 py-1 font-mono text-[11px] text-stone-300 transition hover:border-amber-500/50 hover:text-amber-300"
              >
                {sample.replace("https://", "")}
              </button>
            ))}
          </div>

          {scanning && (
            <div className="mt-5 overflow-hidden rounded-xl border border-amber-500/25 bg-[#0b0c0a]/90 p-3.5">
              <div className="flex items-center justify-between font-mono text-xs text-amber-300">
                <span>{SCAN_STAGES[stageIndex]}</span>
                <span className="animate-pulse">LIVE PROBE</span>
              </div>
              <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-stone-800">
                <div className="h-full w-1/3 rounded-full bg-amber-400 animate-scan-sweep" />
              </div>
            </div>
          )}

          {error && (
            <div className="mt-4 flex items-center gap-2 rounded-xl border border-rose-500/35 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
              <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}
        </section>

        {/* Browser-Local Recent Scans Drawer */}
        {showHistory && (
          <section className="surface-card mt-6 rounded-2xl p-5">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="font-mono text-xs font-semibold uppercase tracking-widest text-amber-300">
                Recent Browser Scans (Stored Locally Only)
              </h2>
              <div className="flex items-center gap-3">
                {history.length > 0 && (
                  <button
                    type="button"
                    onClick={clearLocalHistory}
                    className="inline-flex items-center gap-1 font-mono text-xs text-rose-300 hover:underline"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> CLEAR
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowHistory(false)}
                  className="font-mono text-xs text-stone-400 hover:text-stone-200"
                >
                  CLOSE
                </button>
              </div>
            </div>
            {history.length === 0 ? (
              <p className="text-xs text-stone-400">
                No recent scans in this browser yet. Run a scan above to view it here.
              </p>
            ) : (
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {history.map((item) => (
                  <button
                    key={item.finalUrl}
                    type="button"
                    onClick={() => {
                      setReport(item);
                      setShowHistory(false);
                    }}
                    className="rounded-xl border border-stone-800 bg-[#0b0c0a]/70 p-3 text-left transition hover:border-amber-500/40"
                  >
                    <div className="truncate font-mono text-xs font-semibold text-stone-200">
                      {item.hostname}
                    </div>
                    <div className="mt-0.5 font-mono text-[11px] text-stone-400">
                      Score {item.score}/100 ({item.grade}) · {item.verdict}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </section>
        )}

        {/* Live Scan Report */}
        {report && (
          <div className="mt-6 space-y-6">
            {/* TOP HERO VERDICT */}
            <section
              className={`rounded-2xl p-6 ${
                report.verdict === "High Risk" ? "surface-card-danger" : "surface-card"
              }`}
            >
              <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-col items-center gap-6 sm:flex-row">
                  <SecurityGauge
                    score={report.score}
                    grade={report.grade}
                    verdict={report.verdict}
                  />

                  <div className="space-y-2 text-center sm:text-left">
                    <div className="flex flex-wrap items-center justify-center gap-2 sm:justify-start">
                      <span className="font-mono text-xs uppercase tracking-widest text-stone-400">
                        TARGET HOST:
                      </span>
                      <span className="font-mono text-sm font-semibold text-amber-300">
                        {report.hostname}
                      </span>
                      <a
                        href={report.finalUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-stone-700 px-1.5 py-0.5 font-mono text-[10px] text-stone-400 hover:text-stone-200"
                      >
                        OPEN <ExternalLink className="h-2.5 w-2.5" />
                      </a>
                    </div>

                    <div className="flex flex-wrap items-center justify-center gap-2 sm:justify-start">
                      {report.phishing.detected ? (
                        <span className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-950/60 px-3 py-1 font-mono text-xs font-semibold text-rose-300">
                          <ShieldAlert className="h-4 w-4" />
                          PHISHING / THREAT RISK: {report.phishing.riskLevel.toUpperCase()}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/35 bg-emerald-950/60 px-3 py-1 font-mono text-xs font-semibold text-emerald-300">
                          <ShieldCheck className="h-4 w-4" />
                          NO PHISHING SIGNALS DETECTED
                        </span>
                      )}

                      {report.http.statusCode && (
                        <span className="rounded-lg border border-stone-700/80 bg-stone-900/80 px-2.5 py-1 font-mono text-xs text-stone-300">
                          HTTP {report.http.statusCode} · {report.http.latencyMs}ms
                        </span>
                      )}
                    </div>

                    <p className="max-w-xl text-xs text-stone-400">
                      Final URL:{" "}
                      <span className="font-mono text-stone-300">{report.finalUrl}</span>
                    </p>
                  </div>
                </div>

                <div className="flex flex-col items-stretch gap-2 sm:flex-row lg:flex-col lg:items-end">
                  <button
                    type="button"
                    onClick={handleExportJson}
                    className="inline-flex items-center justify-center gap-2 rounded-lg border border-amber-500/35 bg-amber-500/10 px-3.5 py-2 font-mono text-xs text-amber-300 transition hover:bg-amber-500/20"
                  >
                    <Download className="h-3.5 w-3.5" />
                    EXPORT JSON REPORT
                  </button>
                  <span className="font-mono text-[10px] text-stone-500">
                    SCANNED {new Date(report.scannedAt).toLocaleString()}
                  </span>
                </div>
              </div>

              {/* Phishing Signals & Score Deductions */}
              <div className="mt-6 grid gap-4 border-t border-stone-800/80 pt-5 md:grid-cols-2">
                <div>
                  <h3 className="mb-2.5 font-mono text-[11px] font-semibold uppercase tracking-widest text-stone-400">
                    Phishing &amp; Threat Heuristics ({report.phishing.signals.length})
                  </h3>
                  {report.phishing.signals.length === 0 ? (
                    <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/30 p-3 text-xs text-emerald-300">
                      Passed all URL structure, homograph, brand-impersonation, and credential
                      harvesting checks.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {report.phishing.signals.map((sig) => (
                        <div
                          key={sig.id}
                          className="rounded-xl border border-rose-500/30 bg-rose-950/30 p-3"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-semibold text-rose-300">
                              {sig.title}
                            </span>
                            <span className="rounded border border-rose-500/30 px-1.5 py-0.5 font-mono text-[10px] uppercase text-rose-300">
                              {sig.severity}
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-stone-300">{sig.detail}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="mt-3 grid gap-2 sm:grid-cols-2">
                    <div className="rounded-lg border border-stone-800 bg-[#0b0c0a]/70 p-2.5 font-mono text-[11px]">
                      <div className="text-stone-500">VIRUSTOTAL FEED</div>
                      <div className="mt-0.5 text-stone-300">
                        {report.phishing.externalFeeds.virusTotal}
                      </div>
                    </div>
                    <div className="rounded-lg border border-stone-800 bg-[#0b0c0a]/70 p-2.5 font-mono text-[11px]">
                      <div className="text-stone-500">SAFE BROWSING</div>
                      <div className="mt-0.5 text-stone-300">
                        {report.phishing.externalFeeds.googleSafeBrowsing}
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="mb-2.5 font-mono text-[11px] font-semibold uppercase tracking-widest text-stone-400">
                    Score Telemetry Breakdown
                  </h3>
                  {report.scoreBreakdown.length === 0 ? (
                    <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/30 p-3 text-xs text-emerald-300">
                      100/100 — Zero security deductions recorded.
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {report.scoreBreakdown.map((item, idx) => (
                        <div
                          key={`${item.label}-${idx}`}
                          className="flex items-center justify-between rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 px-3 py-2 text-xs"
                        >
                          <span className="text-stone-300">{item.label}</span>
                          <span className="font-mono font-semibold text-rose-400">
                            {item.delta}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </section>

            {/* 4-Module Deep Intelligence Grid */}
            <div className="grid gap-6 lg:grid-cols-2">
              <section className="surface-card rounded-2xl p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-amber-300">
                    <Lock className="h-4 w-4" />
                    SSL / TLS Certificate
                  </div>
                  <span
                    className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase ${
                      report.ssl.authorized
                        ? "border-emerald-500/30 bg-emerald-950/50 text-emerald-300"
                        : "border-rose-500/30 bg-rose-950/50 text-rose-300"
                    }`}
                  >
                    {report.ssl.authorized ? "TRUSTED" : "UNTRUSTED / OFF"}
                  </span>
                </div>

                <dl className="grid grid-cols-2 gap-3 font-mono text-xs">
                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <dt className="text-[10px] text-stone-500">PROTOCOL</dt>
                    <dd className="mt-1 text-stone-200">{report.ssl.protocol || "None"}</dd>
                  </div>
                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <dt className="text-[10px] text-stone-500">DAYS REMAINING</dt>
                    <dd className="mt-1 text-stone-200">
                      {report.ssl.daysRemaining !== null ? `${report.ssl.daysRemaining}d` : "N/A"}
                    </dd>
                  </div>
                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <dt className="text-[10px] text-stone-500">ISSUER</dt>
                    <dd className="mt-1 truncate text-stone-200">
                      {report.ssl.issuer || "N/A"}
                    </dd>
                  </div>
                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <dt className="text-[10px] text-stone-500">CIPHER</dt>
                    <dd className="mt-1 truncate text-stone-200">
                      {report.ssl.cipher || "N/A"}
                    </dd>
                  </div>
                </dl>
                {report.ssl.error && (
                  <p className="mt-3 font-mono text-xs text-rose-400">
                    TLS Note: {report.ssl.error}
                  </p>
                )}
              </section>

              <section className="surface-card rounded-2xl p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-amber-300">
                    <ShieldCheck className="h-4 w-4" />
                    HTTP Security Headers
                  </div>
                  <span className="font-mono text-[11px] text-stone-400">
                    {report.http.securityHeaders.filter((h) => h.present).length}/
                    {report.http.securityHeaders.length} PRESENT
                  </span>
                </div>

                <div className="space-y-2">
                  {report.http.securityHeaders.map((hdr) => (
                    <div
                      key={hdr.key}
                      className="flex items-start justify-between gap-3 rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 px-3 py-2"
                    >
                      <div className="min-w-0">
                        <div className="font-mono text-xs text-stone-200">{hdr.name}</div>
                        <div className="truncate font-mono text-[10px] text-stone-500">
                          {hdr.present ? hdr.value : hdr.recommendation}
                        </div>
                      </div>
                      <span
                        className={`shrink-0 inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] ${
                          hdr.present
                            ? "bg-emerald-950/60 text-emerald-300"
                            : "bg-amber-950/60 text-amber-300"
                        }`}
                      >
                        {hdr.present ? (
                          <>
                            <CheckCircle2 className="h-3 w-3" /> PASS
                          </>
                        ) : (
                          "MISSING"
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              </section>

              <section className="surface-card rounded-2xl p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-amber-300">
                    <Server className="h-4 w-4" />
                    DNS, Email Spoofing &amp; Network
                  </div>
                  {report.dns.cdnOrWaf && (
                    <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-300">
                      CDN: {report.dns.cdnOrWaf}
                    </span>
                  )}
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <div className="text-[10px] text-stone-500">RESOLVED IPS</div>
                    <div className="mt-1 text-stone-200">
                      {report.dns.resolvedIps.join(", ") || "None"}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                      <div className="text-[10px] text-stone-500">SPF RECORD</div>
                      <div
                        className={`mt-1 ${
                          report.dns.hasSpf ? "text-emerald-300" : "text-amber-300"
                        }`}
                      >
                        {report.dns.hasSpf ? "CONFIGURED" : "MISSING"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                      <div className="text-[10px] text-stone-500">DMARC RECORD</div>
                      <div
                        className={`mt-1 ${
                          report.dns.hasDmarc ? "text-emerald-300" : "text-amber-300"
                        }`}
                      >
                        {report.dns.hasDmarc ? "CONFIGURED" : "MISSING"}
                      </div>
                    </div>
                  </div>

                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <div className="text-[10px] text-stone-500">
                      REDIRECT CHAIN ({report.http.redirectChain.length} HOPS)
                    </div>
                    {report.http.redirectChain.length === 0 ? (
                      <div className="mt-1 text-stone-400">Direct response (no redirects)</div>
                    ) : (
                      <ul className="mt-1 space-y-1 text-[11px] text-stone-300">
                        {report.http.redirectChain.map((hop, i) => (
                          <li key={`${hop.url}-${i}`} className="truncate">
                            [{hop.status}] {hop.url}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </section>

              <section className="surface-card rounded-2xl p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-amber-300">
                    <Cpu className="h-4 w-4" />
                    Tech Stack, Trackers &amp; Metadata
                  </div>
                  <span className="font-mono text-[11px] text-stone-400">
                    <Globe className="mr-1 inline h-3.5 w-3.5" />
                    {report.intelligence.externalLinkCount} EXT LINKS
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <div className="font-mono text-[10px] text-stone-500">PAGE TITLE</div>
                    <div className="mt-1 font-medium text-stone-200">
                      {report.intelligence.title || "No <title> detected"}
                    </div>
                    {report.intelligence.description && (
                      <p className="mt-1 line-clamp-2 text-stone-400">
                        {report.intelligence.description}
                      </p>
                    )}
                  </div>

                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <div className="mb-1.5 font-mono text-[10px] text-stone-500">
                      DETECTED TECHNOLOGIES
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {report.intelligence.techStack.length > 0 ? (
                        report.intelligence.techStack.map((tech) => (
                          <span
                            key={tech}
                            className="rounded border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 font-mono text-[11px] text-amber-200"
                          >
                            {tech}
                          </span>
                        ))
                      ) : (
                        <span className="font-mono text-stone-400">No stack markers exposed</span>
                      )}
                    </div>
                  </div>

                  <div className="rounded-lg border border-stone-800/80 bg-[#0b0c0a]/70 p-3">
                    <div className="mb-1.5 font-mono text-[10px] text-stone-500">
                      THIRD-PARTY TRACKERS &amp; FORMS
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {report.intelligence.trackers.length > 0 ? (
                        report.intelligence.trackers.map((t) => (
                          <span
                            key={t}
                            className="rounded border border-stone-700 bg-stone-800/70 px-2 py-0.5 font-mono text-[11px] text-stone-200"
                          >
                            {t}
                          </span>
                        ))
                      ) : (
                        <span className="font-mono text-emerald-300">
                          No common analytics trackers detected
                        </span>
                      )}
                      {report.intelligence.hasPasswordForm && (
                        <span className="rounded border border-rose-500/35 bg-rose-950/60 px-2 py-0.5 font-mono text-[11px] text-rose-300">
                          <Activity className="mr-1 inline h-3 w-3" />
                          PASSWORD INPUT PRESENT
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </section>
            </div>
          </div>
        )}

        {/* Interactive Phishing URL Anatomy Lab */}
        <section id="phishing-lab" className="surface-card mt-10 rounded-2xl p-6 sm:p-8">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="font-mono text-[11px] uppercase tracking-widest text-amber-400">
                Interactive Phishing Lab
              </span>
              <h2 className="font-display mt-1 text-xl font-bold text-stone-100 sm:text-2xl">
                Click any part of a suspicious URL to see how we catch it
              </h2>
            </div>
            <span className="font-mono text-[11px] text-stone-400">
              CLICK A SEGMENT BELOW
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-stone-800 bg-[#0b0c0a]/90 p-4 font-mono text-sm sm:text-base">
            {ANATOMY_SEGMENTS.map((seg) => {
              const isSelected = activeSegment.id === seg.id;
              return (
                <button
                  key={seg.id}
                  type="button"
                  onClick={() => setActiveSegment(seg)}
                  className={`rounded-md px-2.5 py-1 transition ${
                    isSelected
                      ? "bg-amber-500 text-stone-950 font-semibold shadow-[0_0_16px_rgba(217,155,67,0.35)]"
                      : "bg-stone-900 text-stone-300 hover:bg-stone-800 hover:text-amber-300"
                  }`}
                >
                  {seg.label}
                </button>
              );
            })}
          </div>

          <div className="mt-4 flex flex-col justify-between gap-4 rounded-xl border border-stone-800/90 bg-[#0b0c0a]/70 p-4 sm:flex-row sm:items-center">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-amber-300">
                  {activeSegment.title}
                </span>
                <span className="rounded border border-rose-500/35 bg-rose-950/50 px-2 py-0.5 font-mono text-[10px] uppercase text-rose-300">
                  {activeSegment.risk}
                </span>
              </div>
              <p className="mt-1.5 text-sm text-stone-300">{activeSegment.explanation}</p>
            </div>
            <div className="shrink-0 rounded-lg border border-stone-800 bg-stone-900/70 px-3.5 py-2 text-center font-mono">
              <div className="text-[10px] text-stone-500">SCORE IMPACT</div>
              <div className="text-sm font-semibold text-rose-400">
                {activeSegment.deduction}
              </div>
            </div>
          </div>
        </section>

        {/* Interactive Capabilities Explorer */}
        <section id="capabilities" className="mt-10 grid gap-6 lg:grid-cols-12">
          <div className="surface-card rounded-2xl p-6 lg:col-span-5">
            <span className="font-mono text-[11px] uppercase tracking-widest text-amber-400">
              Inspection Architecture
            </span>
            <h2 className="font-display mt-1 text-xl font-bold text-stone-100 sm:text-2xl">
              Everything checked on every scan
            </h2>
            <p className="mt-2 text-sm text-stone-400">
              Select a module to inspect what Veritas Lens verifies in real time without storing
              your browsing history on any server.
            </p>

            <div className="mt-5 space-y-2">
              {CAPABILITIES.map((cap) => {
                const Icon = cap.icon;
                const active = activeCap.id === cap.id;
                return (
                  <button
                    key={cap.id}
                    type="button"
                    onClick={() => setActiveCap(cap)}
                    className={`flex w-full items-center gap-3 rounded-xl border px-3.5 py-3 text-left transition ${
                      active
                        ? "border-amber-500/50 bg-amber-500/10 text-stone-100"
                        : "border-stone-800/80 bg-[#0b0c0a]/60 text-stone-300 hover:border-stone-700"
                    }`}
                  >
                    <Icon
                      className={`h-4 w-4 shrink-0 ${
                        active ? "text-amber-400" : "text-stone-500"
                      }`}
                    />
                    <span className="font-mono text-xs font-medium">{cap.title}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="surface-card flex flex-col justify-between rounded-2xl p-6 sm:p-8 lg:col-span-7">
            <div>
              <div className="inline-flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 font-mono text-xs text-amber-300">
                <activeCap.icon className="h-4 w-4" />
                {activeCap.title}
              </div>
              <h3 className="font-display mt-4 text-2xl font-bold text-stone-100">
                {activeCap.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-stone-300">
                {activeCap.summary}
              </p>

              <div className="mt-6 grid gap-3 sm:grid-cols-2">
                {activeCap.checks.map((check) => (
                  <div
                    key={check}
                    className="flex items-start gap-2.5 rounded-xl border border-stone-800/80 bg-[#0b0c0a]/70 p-3.5"
                  >
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                    <span className="text-xs leading-relaxed text-stone-200">{check}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-8 flex flex-wrap items-center justify-between gap-4 border-t border-stone-800/80 pt-5">
              <div>
                <div className="font-mono text-[11px] uppercase tracking-wider text-stone-400">
                  Privacy &amp; Independence Guarantee
                </div>
                <p className="mt-0.5 text-xs text-stone-400">
                  No sign-in. No database. No tracking cookies. Your recent scans stay solely in
                  your browser.
                </p>
              </div>
              <span className="rounded-md border border-emerald-500/30 bg-emerald-950/50 px-2.5 py-1 font-mono text-[11px] text-emerald-300">
                100% STATELESS
              </span>
            </div>
          </div>
        </section>
      </main>

      <footer className="relative z-10 mt-12 border-t border-stone-200/10 bg-[#0b0c0a]/80 py-6">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-2 px-4 font-mono text-[11px] text-stone-400 sm:flex-row sm:px-6">
          <span>VERITAS // LENS — INDEPENDENT WEBSITE SECURITY &amp; PHISHING SCANNER</span>
          <span className="text-stone-300">
            Made By <span className="text-amber-400 font-semibold">Himanshu Singh</span> Using{" "}
            <span className="text-stone-100">Next.js</span>
          </span>
        </div>
      </footer>
    </div>
  );
}
