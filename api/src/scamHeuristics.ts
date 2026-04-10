/** Hardcoded phrase patterns with associated risk weights and plain-language descriptions. */
export const TEXT_PATTERNS = [
  { id: "gift_card", weight: 3.5, pattern: /\bgift[\s-]*card(s)?\b/i, description: "it asks for payment via gift cards" },
  { id: "wire_transfer", weight: 4.0, pattern: /\bwire\s+transfer\b/i, description: "it requests a wire transfer" },
  { id: "verify_account", weight: 3.0, pattern: /\bverify\s+your\s+(account|identity)\b/i, description: "it asks you to verify your identity through a link" },
  { id: "urgent_action", weight: 2.5, pattern: /\burgent\b.*\b(act\s+now|respond\s+immediately|within\s+\d+)\b/i, description: "it uses urgent language to pressure you into acting quickly" },
  { id: "ssn_request", weight: 5.0, pattern: /\b(social\s+security|SSN)\b.*\b(confirm|provide|enter)\b/i, description: "it asks for your Social Security Number" },
  { id: "click_link_now", weight: 2.0, pattern: /\bclick\s+(this\s+)?(link|here)\s+now\b/i, description: "it pressures you to click a link immediately" },
  { id: "prize_winner", weight: 4.5, pattern: /\b(you('ve| have)\s+)?won\b.*\b(prize|lottery|jackpot)\b/i, description: "it claims you have won a prize or lottery" },
  { id: "inheritance_scam", weight: 4.5, pattern: /\b(deceased|inheritance|next\s+of\s+kin|million\s+dollars)\b/i, description: "it mentions an inheritance or deceased relative" },
  { id: "crypto_urgency", weight: 4.0, pattern: /\b(send|transfer)\s+(bitcoin|BTC|crypto|USDT)\b/i, description: "it requests a cryptocurrency transfer" },
  { id: "password_reset_phish", weight: 3.5, pattern: /\b(unusual\s+activity|password\s+expired)\b.*\b(click|link)\b/i, description: "it claims there is unusual activity on your account" },
] as const;

const MAX_INPUT_CHARS = 50_000;

export type TextAnalysisResult = {
  score: number;
  matches: { id: string; description: string }[];
};

export function analyzeText(raw: string): TextAnalysisResult {
  const text = raw.slice(0, MAX_INPUT_CHARS);
  const matches: { id: string; description: string }[] = [];
  let totalWeight = 0;

  for (const { id, weight, pattern, description } of TEXT_PATTERNS) {
    if (pattern.test(text)) {
      matches.push({ id, description });
      totalWeight += weight;
    }
  }

  // Cap initial heuristic score at 10
  const score = Math.min(10, totalWeight);

  return { score, matches };
}
