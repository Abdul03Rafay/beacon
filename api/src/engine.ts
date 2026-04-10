import { analyzeText } from "./scamHeuristics.js";
import type { TextAnalysisResult } from "./scamHeuristics.js";
import { analyzeURL } from "./domainHeuristics.js";
import type { URLAnalysisResult } from "./domainHeuristics.js";

export interface AnalysisInput {
  text?: string;
  url?: string;
}

export interface FinalAnalysisResult {
  score: number; // 0 to 100
  verdict: "Safe" | "Suspicious" | "Likely Scam";
  explanation: string;
  details: {
    textAnalysis: TextAnalysisResult | null;
    urlAnalysis: URLAnalysisResult | null;
  };
}

/**
 * Generates a compassionate, non-technical explanation for elderly users.
 */
function generateExplanation(textRes: TextAnalysisResult | null, urlRes: URLAnalysisResult | null): string {
  if (!textRes && !urlRes) return "No data was provided to check.";

  const reasons: string[] = [];

  if (urlRes && urlRes.score > 0) {
    urlRes.indicators.forEach(ind => reasons.push(ind.description));
  }

  if (textRes && textRes.score > 0) {
    textRes.matches.forEach(match => reasons.push(match.description));
  }

  if (reasons.length === 0) {
    return "We couldn't find any obvious signs of a scam on this page. However, you should always stay cautious when entering personal information online.";
  }

  // Combine reasons into a friendly sentence
  const primaryReason = reasons[0];
  const secondaryReason = reasons.length > 1 ? ` Furthermore, ${reasons[1]}.` : "";
  
  return `This page looks suspicious because ${primaryReason}.${secondaryReason} For your safety, we recommend not providing any personal or financial information here.`;
}

/**
 * Orchestrates the analysis and computes a final 0-100 score.
 */
export function runAnalysis(input: AnalysisInput): FinalAnalysisResult {
  const textRes = input.text ? analyzeText(input.text) : null;
  const urlRes = input.url ? analyzeURL(input.url) : null;

  let rawScore = 0;
  
  if (textRes && urlRes) {
    rawScore = Math.max(textRes.score, urlRes.score);
    if (textRes.score > 3 && urlRes.score > 3) {
      rawScore += 1.5;
    }
  } else if (textRes) {
    rawScore = textRes.score;
  } else if (urlRes) {
    rawScore = urlRes.score;
  }

  // Normalize to 0-100 scale (input scores are capped at 10)
  const finalScore = Math.min(100, Math.round(rawScore * 10));

  // Determine verdict based on 0-100 scale
  let verdict: FinalAnalysisResult["verdict"] = "Safe";
  if (finalScore >= 70) verdict = "Likely Scam";
  else if (finalScore >= 35) verdict = "Suspicious";

  return {
    score: finalScore,
    verdict,
    explanation: generateExplanation(textRes, urlRes),
    details: {
      textAnalysis: textRes,
      urlAnalysis: urlRes
    }
  };
}
