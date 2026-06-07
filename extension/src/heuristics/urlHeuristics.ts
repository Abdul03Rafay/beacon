/**
 * urlHeuristics.ts
 *
 * Analyses the URL of the current page (the string itself — not the page
 * content or any link destinations) and returns a HeuristicResult.
 *
 * All rules are derived from EDA on the PhiUSIIL dataset (~235K URLs,
 * 57% legitimate / 43% phishing). See HEURISTICS.md for full rationale.
 *
 * Scoring (0–10, capped):
 *   0–3  → safe
 *   4–6  → uncertain
 *   7+   → scam
 */

import type { HeuristicResult } from "../types/heuristics";
import { toVerdict } from "./contentHeuristics";

// ─── EDA-derived thresholds ──────────────────────────────────────────────────

/** 99th percentile of phishing URL length in PhiUSIIL — 100% phishing above this. */
const URL_LENGTH_HARD = 144;

/** Softer threshold (phishing 75th percentile) — used only in compound rules. */
const URL_LENGTH_SOFT = 75;

/** Min percent-encoded sequences in hostname+path to flag obfuscation. */
const PERCENT_ENCODED_MIN = 3;

/** Min hyphens in hostname to flag subdomain-stacking attacks. */
const HOST_HYPHENS_MIN = 3;

// ─── Internal types ──────────────────────────────────────────────────────────

interface RuleResult {
    triggered: boolean;
    finding: string;
}

interface Rule {
    id: string;
    tier: 1 | 2;
    weight: number;
    check: (url: string) => RuleResult;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseHostname(url: string): string {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

// ─── Tier 1 rules — standalone ───────────────────────────────────────────────
// Each fires independently. Maps to a binary feature with 100% phishing rate
// in the EDA — no legitimate site in the dataset matched these patterns.

const TIER_1_RULES: Rule[] = [
    {
        id: "isdomainip",
        tier: 1,
        weight: 10,
        check(url) {
            const hostname = parseHostname(url);
            // Bare IPv4 — no legitimate public-facing site uses one
            const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
            return {
                triggered: isIp,
                finding: `URL uses a raw IP address (${hostname}) instead of a domain name`,
            };
        },
    },

    {
        id: "hasobfuscation",
        tier: 1,
        weight: 8,
        check(url) {
            try {
                const parsed = new URL(url);

                // Credential injection: http://paypal.com@evil.com — browser resolves evil.com
                if (parsed.username !== "" || parsed.password !== "") {
                    return {
                        triggered: true,
                        finding: `URL contains '@' credential-injection — actual host is '${parsed.hostname}'`,
                    };
                }

                // Percent-encoded characters in the hostname itself (invalid per RFC 3986)
                if (/%[0-9a-fA-F]{2}/.test(parsed.hostname)) {
                    return {
                        triggered: true,
                        finding: `URL hostname contains percent-encoded characters (obfuscation): ${parsed.hostname}`,
                    };
                }
            } catch {
                // Unparseable URLs fall through to other rules
            }
            return { triggered: false, finding: "" };
        },
    },

    {
        id: "urlLengthHard",
        tier: 1,
        weight: 7,
        check(url) {
            return {
                triggered: url.length > URL_LENGTH_HARD,
                finding: `URL is ${url.length} chars, exceeding the ${URL_LENGTH_HARD}-char phishing threshold (EDA Finding 3.9: 100% precision above this value)`,
            };
        },
    },
];

// ─── Tier 2 rules — compound ─────────────────────────────────────────────────
// Require two independent weak signals simultaneously. Neither signal alone
// is precise enough; together they raise confidence significantly.
// (Brian Ha's insight: "a URL being long alone is a red herring — combine it
//  with another weak feature and it becomes meaningful".)

const TIER_2_RULES: Rule[] = [
    {
        id: "urlLengthWithComplexity",
        tier: 2,
        weight: 4,
        check(url) {
            if (url.length <= URL_LENGTH_SOFT) {
                return { triggered: false, finding: "" };
            }
            const hostname = parseHostname(url);
            // Exclude query string — encoded params (?q=hello%20world) are normal on
            // legitimate sites and would cause false positives if counted here.
            const urlWithoutQuery = url.split("?")[0];
            const percentEncoded = (urlWithoutQuery.match(/%[0-9a-fA-F]{2}/g) ?? []).length;
            const hostHyphens = (hostname.match(/-/g) ?? []).length;

            const complexityTriggered =
                percentEncoded >= PERCENT_ENCODED_MIN || hostHyphens >= HOST_HYPHENS_MIN;

            return {
                triggered: complexityTriggered,
                finding:
                    `Long URL (${url.length} chars) with suspicious structure — ` +
                    `${percentEncoded} %-encoded sequences in path, ${hostHyphens} hyphens in hostname`,
            };
        },
    },
];

// ─── Main export ─────────────────────────────────────────────────────────────

export function analyzeUrl(url: string): HeuristicResult {
    const findings: string[] = [];
    let score = 0;

    for (const rule of [...TIER_1_RULES, ...TIER_2_RULES]) {
        const result = rule.check(url);
        if (result.triggered) {
            score += rule.weight;
            findings.push(`[Tier ${rule.tier}] ${result.finding}`);
        }
    }

    // Invert to a safety score: 10 = no threats detected, 0 = maximum threat.
    score = 10 - Math.min(score, 10);
    const { verdict, explanation } = toVerdict(score);
    return { score, verdict, explanation, findings, source: "url" };
}
