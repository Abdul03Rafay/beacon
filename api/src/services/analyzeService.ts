import { AnalyzeRequest, AnalyzeResponse } from "../types/api.js";
import { Provider } from "../providers/types.js";
import { MockProvider } from "../providers/mockProvider.js";

type ModelChoice = "external_llm" | "custom_model";

// Routing rules 
function selectModel(heuristicScore: number, context: string): ModelChoice {
  // High risk OR email → External LLM call
  if (heuristicScore >= 0.85 || context === "email_body") {
    return "external_llm";
  }

  //  Low risk → Custom model
  return "custom_model";
}

export class AnalyzeService {
  private externalLlm: Provider;
  private customModel: Provider;

  constructor() {
    // Using mock provider for now
    this.externalLlm = new MockProvider();
    this.customModel = new MockProvider();
  }

  async analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
    const model = selectModel(request.heuristic_score, request.context);

    const provider = model === "external_llm" ? this.externalLlm : this.customModel;

    return provider.analyze(request);
  }
}
