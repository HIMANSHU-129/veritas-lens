"use client";

interface SecurityGaugeProps {
  score: number;
  grade: string;
  verdict: "Safe" | "Caution" | "High Risk";
}

export function SecurityGauge({ score, grade, verdict }: SecurityGaugeProps) {
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference - (clamped / 100) * circumference;

  const palette =
    verdict === "Safe"
      ? {
          stroke: "#52b788",
          glow: "rgba(82, 183, 136, 0.35)",
          text: "text-emerald-300",
          badge: "bg-emerald-950/70 text-emerald-300 border-emerald-500/30",
        }
      : verdict === "Caution"
        ? {
            stroke: "#d99b43",
            glow: "rgba(217, 155, 67, 0.35)",
            text: "text-amber-300",
            badge: "bg-amber-950/70 text-amber-300 border-amber-500/35",
          }
        : {
            stroke: "#e05252",
            glow: "rgba(224, 82, 82, 0.4)",
            text: "text-rose-300",
            badge: "bg-rose-950/70 text-rose-300 border-rose-500/35",
          };

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex h-36 w-36 items-center justify-center">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 140 140">
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke="rgba(214, 206, 190, 0.12)"
            strokeWidth="10"
          />
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={palette.stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{
              filter: `drop-shadow(0 0 8px ${palette.glow})`,
              transition: "stroke-dashoffset 700ms cubic-bezier(0.22, 1, 0.36, 1)",
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-mono text-3xl font-semibold tracking-tight ${palette.text}`}>
            {clamped}
          </span>
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-stone-400">
            GRADE {grade}
          </span>
        </div>
      </div>
      <span
        className={`mt-2 inline-flex items-center rounded-md border px-2.5 py-0.5 font-mono text-xs uppercase tracking-wider ${palette.badge}`}
      >
        {verdict}
      </span>
    </div>
  );
}
