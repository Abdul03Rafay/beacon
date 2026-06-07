// Manual test suite for contentHeuristics.ts
// Covers CONTENT-only rules: sparsity + meta description, scam phrase detection.
// URL rules are tested in urlHeuristics.test.ts.
// Link rules are tested in linkHeuristics.test.ts.

import { analyzeContent } from "./contentHeuristics";
import type { ExtractedPageData } from "../types/heuristics";

function runTest(name: string, pageData: ExtractedPageData): void {
    console.log("=================================================================");
    console.log(`TEST: ${name}`);
    console.log("-----------------------------------------------------------------");
    const result = analyzeContent(pageData);
    console.log(`Score:       ${result.score}`);
    console.log(`Verdict:     ${result.verdict}`);
    console.log(`Explanation: ${result.explanation}`);
    if (result.findings.length === 0) {
        console.log("Findings:    (none)");
    } else {
        console.log("Findings:");
        for (const finding of result.findings) {
            console.log(`  - ${finding}`);
        }
    }
    console.log("");
}

// ─── Baseline ────────────────────────────────────────────────────────────────

// Content-rich legitimate page. No rules should fire.
// Expected: score 0, "safe".
runTest("Safe page — Wikipedia article", {
    url: "https://en.wikipedia.org/wiki/Moon",
    title: "Moon - Wikipedia",
    metaDescription: "The Moon is Earth's only natural satellite.",
    textContent:
        "The Moon is Earth's only natural satellite. It is the fifth largest " +
        "satellite in the Solar System and the largest relative to its parent planet.",
    links: [],
});

// ─── sparsityNoMeta ──────────────────────────────────────────────────────────

// Very little body text AND no meta description.
// Expected: score 3, "safe" (single content rule — needs another signal to reach uncertain).
runTest("sparsityNoMeta — Sparse page with no meta", {
    url: "https://suspicious-login-page.com/",
    title: "Login",
    metaDescription: "",
    textContent: "Enter your details.",
    links: [],
});

// Sparse + no meta + one scam phrase in title — compound content signals stack.
// Expected: score 6+, "uncertain".
runTest("sparsityNoMeta + scam phrase in title", {
    url: "https://totally-not-a-scam.com/",
    title: "Urgent action required",
    metaDescription: "",
    textContent: "Click the link below to secure your account.",
    links: [],
});

// Page with meta description but sparse text — should NOT fire sparsityNoMeta
// (both conditions required). Expected: score 0, "safe".
runTest("sparsityNoMeta — Sparse text but has meta (no flag)", {
    url: "https://example.com/landing",
    title: "Welcome",
    metaDescription: "A short but descriptive page summary.",
    textContent: "Enter your details.",
    links: [],
});

// ─── Scam phrase detection ────────────────────────────────────────────────────

// Multiple scam phrases across title, meta, and body.
// Expected: high score, "scam".
runTest("Scam phrases — Multiple phrases across all fields", {
    url: "https://free-prize-winner.xyz/claim",
    title: "Congratulations you are our winner!",
    metaDescription: "You have won a brand new iPhone! Claim your prize today!",
    textContent:
        "Click here to claim your free gift! Act now, this is a limited time offer. " +
        "You have won a $1000 gift card!",
    links: [],
});

// One phrase in title only — tests the 3-point title weighting.
// Expected: score 3, "safe".
runTest("Scam phrases — Single phrase in title only", {
    url: "https://example.com",
    title: "You have won a prize",
    metaDescription: "A normal description of a normal page.",
    textContent: "This is the body of a normal page with nothing suspicious.",
    links: [],
});

// One phrase in body only — tests the 2-point body weighting.
// Expected: score 2, "safe".
runTest("Scam phrases — Single phrase in body only", {
    url: "https://example.com/news",
    title: "Today's Top Stories",
    metaDescription: "The latest news and updates.",
    textContent: "Act now to take advantage of this article before it expires.",
    links: [],
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

// All fields empty — function should not throw.
// Expected: score 0, "safe".
runTest("Edge case — Completely empty page", {
    url: "",
    title: "",
    metaDescription: "",
    textContent: "",
    links: [],
});
