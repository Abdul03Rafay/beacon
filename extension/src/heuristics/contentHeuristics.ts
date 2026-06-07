/**
 * contentHeuristics.ts
 *
 * Analyses the CONTENT of the current page (text, title, meta description)
 * and returns a HeuristicResult.
 *
 * Scope: page content only. URL analysis → urlHeuristics.ts.
 *                           Link analysis → linkHeuristics.ts.
 *
 * Rules are derived from EDA on the PhiUSIIL dataset (~235K URLs).
 * See HEURISTICS.md for full rationale and EDA references.
 *
 * Scoring (0–10, capped):
 *   0–3  → safe
 *   4–6  → uncertain
 *   7+   → scam
 */

import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";

// ─── EDA-derived threshold ───────────────────────────────────────────────────

/**
 * Body text length below which a page is "structurally sparse".
 * Proxy for largestlinelength and lineofcode — the two dominant EDA features
 * (separation score 1.464, ~3× stronger than URL features). Phishing pages
 * are thin templates; legitimate pages are content-rich.
 */
const SPARSE_TEXT_MAX = 200;

// ─── Internal types ──────────────────────────────────────────────────────────

interface RuleResult {
    triggered: boolean;
    finding: string;
}

interface Rule {
    id: string;
    weight: number;
    check: (data: ExtractedPageData) => RuleResult;
}

// ─── Content structure rules ──────────────────────────────────────────────────
// Compound rule — requires two weak content signals simultaneously.
// hasdescription correlates with legitimacy at r=0.69 in the EDA.

const CONTENT_RULES: Rule[] = [
    {
        id: "sparsityNoMeta",
        weight: 3,
        check(data) {
            const textLength = data.textContent.trim().length;
            const isSparse = textLength < SPARSE_TEXT_MAX;
            const noMeta = data.metaDescription.trim().length === 0;
            return {
                triggered: isSparse && noMeta,
                finding:
                    `Sparse page: ${textLength} chars of body text and no meta description ` +
                    `(phishing pages are thin templates; legitimate pages are content-rich)`,
            };
        },
    },
];

// ─── Scam phrase detection ────────────────────────────────────────────────────
// Content-based signal. Phrases in title/meta weighted higher because
// attackers deliberately craft those fields to deceive users.

const SCAM_PHRASES: readonly string[] = [
    "you have won",
    "you've won",
    "congratulations, you won",
    "claim your prize",
    "click here to claim",
    "urgent action required",
    "act now",
    "limited time offer",
    "exclusive deal",
    "send a wire transfer",
    "you are the lucky winner",
    "congratulations you are our winner",
];

function findScamPhrases(text: string): string[] {
    const lower = text.toLowerCase();
    return SCAM_PHRASES.filter(phrase => lower.includes(phrase));
}

// ─── Score → Verdict ─────────────────────────────────────────────────────────
// Score is a SAFETY score (0–10): higher = safer, lower = more suspicious.
// Exported so content.ts can reuse it in combineResults, and urlHeuristics /
// linkHeuristics can import it as the single source of truth for thresholds.

export function toVerdict(score: number): {
    verdict: HeuristicResult["verdict"];
    explanation: string;
} {
    if (score >= 7) {
        return {
            verdict: "safe",
            explanation: "No significant phishing indicators detected.",
        };
    }
    if (score >= 4) {
        return {
            verdict: "uncertain",
            explanation:
                "Multiple signals detected. Exercise caution and verify the site independently.",
        };
    }
    return {
        verdict: "scam",
        explanation:
            "Strong phishing indicators detected. Avoid entering credentials or interacting with this page.",
    };
}

// ─── Main export ─────────────────────────────────────────────────────────────

/**
 * Analyses extracted page content and returns a phishing risk score (0–10).
 *
 * Execution order:
 *   1. Content structure rules (sparsity + missing meta description)
 *   2. Scam phrase detection (title, meta description, body text)
 */
export function analyzeContent(pageData: ExtractedPageData): HeuristicResult {
    const findings: string[] = [];
    let score = 0;

    // 1 — Content structure rules
    for (const rule of CONTENT_RULES) {
        const result = rule.check(pageData);
        if (result.triggered) {
            score += rule.weight;
            findings.push(result.finding);
        }
    }

    // 2 — Scam phrase detection
    // Title and meta description are high-prominence fields attackers craft
    // intentionally → weighted at 3. Body text is lower prominence → weighted at 2.
    const titleMatches = findScamPhrases(pageData.title);
    const metaMatches  = findScamPhrases(pageData.metaDescription);
    const bodyMatches  = findScamPhrases(pageData.textContent);

    for (const phrase of titleMatches) {
        score += 3;
        findings.push(`Scam phrase in title: "${phrase}"`);
    }
    for (const phrase of metaMatches) {
        score += 3;
        findings.push(`Scam phrase in meta description: "${phrase}"`);
    }
    for (const phrase of bodyMatches) {
        score += 2;
        findings.push(`Scam phrase in page text: "${phrase}"`);
    }

    // Invert to a safety score: 10 = no threats detected, 0 = maximum threat.
    score = 10 - Math.min(score, 10);
    const { verdict, explanation } = toVerdict(score);
    return { score, verdict, explanation, findings, source: "content" };
}
