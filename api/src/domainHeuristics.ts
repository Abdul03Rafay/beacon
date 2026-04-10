/** Suspicious TLDs that are frequently used in phishing campaigns. */
const SUSPICIOUS_TLDS = [
  ".top", ".xyz", ".click", ".win", ".bid", ".zip", ".review", ".icu", ".best", ".loan"
];

/** Keywords in the hostname that are often indicators of scammy landing pages. */
const SCAMMY_HOST_KEYWORDS = [
  "verify", "secured", "login", "update", "account", "support", "service", "safety", "help", "claim"
];

export type URLAnalysisResult = {
  score: number;
  indicators: string[];
};

export function analyzeURL(urlStr: string): URLAnalysisResult {
  const indicators: string[] = [];
  let score = 0;

  try {
    const url = new URL(urlStr);
    const hostname = url.hostname.toLowerCase();

    // 1. Check for suspicious TLDs
    const matchedTLD = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
    if (matchedTLD) {
      score += 4.0;
      indicators.push(`suspicious_tld:${matchedTLD}`);
    }

    // 2. Check for excessive subdomains (often used for obfuscation)
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount >= 4) {
      score += 3.0;
      indicators.push("excessive_subdomains");
    }

    // 3. Check for scam keywords in hostname
    for (const keyword of SCAMMY_HOST_KEYWORDS) {
      if (hostname.includes(keyword)) {
        score += 2.0;
        indicators.push(`scam_keyword_in_host:${keyword}`);
      }
    }

    // 4. Look-alike indicators (hyphens in host often used in phishing)
    if (hostname.includes("-") && hostname.split(".").length > 2) {
      score += 1.5;
      indicators.push("suspicious_hyphenation");
    }

  } catch (e) {
    // If URL parsing fails, we treat it as high risk if it looks like a scam link
    return { score: 1.0, indicators: ["invalid_url_format"] };
  }

  return { 
    score: Math.min(10, score), 
    indicators 
  };
}
