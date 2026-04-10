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
  indicators: { id: string; description: string }[];
};

const INDICATOR_DESCRIPTIONS: Record<string, string> = {
  "suspicious_tld": "it uses an unusual web address often associated with scams",
  "excessive_subdomains": "the web address is overly complex and likely trying to hide its true destination",
  "scam_keyword_in_host": "the address contains words often used to trick people into providing sensitive info",
  "suspicious_hyphenation": "the web address is structured in a suspicious way to mimic a real company",
  "invalid_url_format": "the address provided is not a valid format and could be dangerous"
};

export function analyzeURL(urlStr: string): URLAnalysisResult {
  const indicators: { id: string; description: string }[] = [];
  let score = 0;

  try {
    const url = new URL(urlStr);
    const hostname = url.hostname.toLowerCase();

    // 1. Check for suspicious TLDs
    const matchedTLD = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
    if (matchedTLD) {
      score += 4.0;
      indicators.push({ 
        id: "suspicious_tld", 
        description: `${INDICATOR_DESCRIPTIONS["suspicious_tld"]} (${matchedTLD})` 
      });
    }

    // 2. Check for excessive subdomains (often used for obfuscation)
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount >= 4) {
      score += 3.0;
      indicators.push({ 
        id: "excessive_subdomains", 
        description: INDICATOR_DESCRIPTIONS["excessive_subdomains"] 
      });
    }

    // 3. Check for scam keywords in hostname
    for (const keyword of SCAMMY_HOST_KEYWORDS) {
      if (hostname.includes(keyword)) {
        score += 2.0;
        indicators.push({ 
          id: "scam_keyword_in_host", 
          description: `${INDICATOR_DESCRIPTIONS["scam_keyword_in_host"]}: "${keyword}"` 
        });
      }
    }

    // 4. Look-alike indicators (hyphens in host often used in phishing)
    if (hostname.includes("-") && hostname.split(".").length > 2) {
      score += 1.5;
      indicators.push({ 
        id: "suspicious_hyphenation", 
        description: INDICATOR_DESCRIPTIONS["suspicious_hyphenation"] 
      });
    }

  } catch (e) {
    // If URL parsing fails, we treat it as high risk if it looks like a scam link
    return { 
      score: 1.0, 
      indicators: [{ id: "invalid_url_format", description: INDICATOR_DESCRIPTIONS["invalid_url_format"] }] 
    };
  }

  return { 
    score: Math.min(10, score), 
    indicators 
  };
}
