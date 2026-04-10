import { analyzeText } from "./scamHeuristics.js";
import { analyzeURL } from "./domainHeuristics.js";

export interface AnalysisInput {
  text?: string;
  url?: string;
}

export interface FinalAnalysisResult {
  score: number; // 0.0 to 10.0
  verdict: "Safe" | "Suspicious" | "Scam";
  details: {
    textAnalysis: {
      score: number;
      matches: string[];
    } | null;
    urlAnalysis: {
      score: number;
      indicators: string[];
    } | null;
  };
}

/**
 * Orchestrates the analysis using available scanners and computes a final score.
 */
export function runAnalysis(input: AnalysisInput): FinalAnalysisResult {
  const textRes = input.text ? analyzeText(input.text) : null;
  const urlRes = input.url ? analyzeURL(input.url) : null;

  // Compute weighted score
  // If we have both, we take a blend, but weight URL reputation heavily
  let compositeScore = 0;
  
  if (textRes && urlRes) {
    // Both available: Take the higher of the two, but boost if both are suspicious
    compositeScore = Math.max(textRes.score, urlRes.score);
    if (textRes.score > 3 && urlRes.score > 3) {
      compositeScore += 1.5; // Combo boost
    }
  } else if (textRes) {
    compositeScore = textRes.score;
  } else if (urlRes) {
    compositeScore = urlRes.score;
  }

  // Ensure it's capped at 10.0
  compositeScore = Math.min(10, compositeScore);

  // Determine verdict
  let verdict: FinalAnalysisResult["verdict"] = "Safe";
  if (compositeScore >= 7.0) verdict = "Scam";
  else if (compositeScore >= 3.5) verdict = "Suspicious";

  return {
    score: Number(compositeScore.toFixed(1)),
    verdict,
    details: {
      textAnalysis: textRes,
      urlAnalysis: urlRes
    }
  };
}
