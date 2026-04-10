/** Hardcoded phrase patterns with associated risk weights. */
export const TEXT_PATTERNS = [
  { id: "gift_card", weight: 3.5, pattern: /\bgift[\s-]*card(s)?\b/i },
  { id: "wire_transfer", weight: 4.0, pattern: /\bwire\s+transfer\b/i },
  { id: "verify_account", weight: 3.0, pattern: /\bverify\s+your\s+(account|identity)\b/i },
  { id: "urgent_action", weight: 2.5, pattern: /\burgent\b.*\b(act\s+now|respond\s+immediately|within\s+\d+)\b/i },
  { id: "ssn_request", weight: 5.0, pattern: /\b(social\s+security|SSN)\b.*\b(confirm|provide|enter)\b/i },
  { id: "click_link_now", weight: 2.0, pattern: /\bclick\s+(this\s+)?(link|here)\s+now\b/i },
  { id: "prize_winner", weight: 4.5, pattern: /\b(you('ve| have)\s+)?won\b.*\b(prize|lottery|jackpot)\b/i },
  { id: "inheritance_scam", weight: 4.5, pattern: /\b(deceased|inheritance|next\s+of\s+kin|million\s+dollars)\b/i },
  { id: "crypto_urgency", weight: 4.0, pattern: /\b(send|transfer)\s+(bitcoin|BTC|crypto|USDT)\b/i },
  { id: "password_reset_phish", weight: 3.5, pattern: /\b(unusual\s+activity|password\s+expired)\b.*\b(click|link)\b/i },
] as const;

const MAX_INPUT_CHARS = 50_000;

export type TextAnalysisResult = {
  score: number;
  matches: string[];
};

export function analyzeText(raw: string): TextAnalysisResult {
  const text = raw.slice(0, MAX_INPUT_CHARS);
  const matches: string[] = [];
  let totalWeight = 0;

  for (const { id, weight, pattern } of TEXT_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(id);
      totalWeight += weight;
    }
  }

  // Cap initial heuristic score at 10
  const score = Math.min(10, totalWeight);

  return { score, matches };
}
