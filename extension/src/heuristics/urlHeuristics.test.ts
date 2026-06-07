// Manual test suite for urlHeuristics.ts
// Covers Tier 1 (isdomainip, hasobfuscation, urlLengthHard) and
// Tier 2 (urlLengthWithComplexity) rules.

import { analyzeUrl } from "./urlHeuristics";

function runTest(name: string, url: string): void {
    console.log("=================================================================");
    console.log(`TEST: ${name}`);
    console.log(`URL:  ${url}`);
    console.log("-----------------------------------------------------------------");
    const result = analyzeUrl(url);
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

// Clean HTTPS domain — no rules should fire.
// Expected: score 0, "safe".
runTest("Safe — Clean HTTPS domain", "https://en.wikipedia.org/wiki/Moon");

// ─── Tier 1: isdomainip ───────────────────────────────────────────────────────

// URL uses a raw IPv4 address. EDA: 100% phishing rate.
// Expected: score 10, "scam".
runTest("Tier 1 — IP address URL", "http://192.168.1.105/login");

// ─── Tier 1: hasobfuscation ──────────────────────────────────────────────────

// Credential-injection: http://paypal.com@evil-phishing.xyz/login
// Browser resolves evil-phishing.xyz; URL visually resembles paypal.com.
// Expected: score 8, "scam".
runTest("Tier 1 — @ credential injection", "http://paypal.com@evil-phishing.xyz/login");

// ─── Tier 1: urlLengthHard ───────────────────────────────────────────────────

// URL exceeds 144 chars (99th percentile of phishing distribution).
// EDA Finding 3.9: 100% phishing above this threshold.
// Expected: score 7, "scam".
runTest(
    "Tier 1 — URL exceeds 144-char hard threshold",
    "https://secure-login.paypal-accounts-verify.com/confirm/identity/step2?token=aB3xK9mNqR7vL2pW5yZ1cF4hJ8dU6tE0sG&session=mNqR7vL2pWxK9mNqR7vL2pWxy"
);

// ─── Tier 2: urlLengthWithComplexity ─────────────────────────────────────────

// URL over 75 chars with 3+ hyphens in hostname (subdomain stacking).
// Expected: score 4, "uncertain".
runTest(
    "Tier 2 — Long URL with hyphen-stacked hostname",
    "https://secure-paypal-login-verify.attacker-phishing.com/account/verify?session=abc123"
);

// URL over 75 chars with percent-encoded sequences in the PATH (3+ %XX).
// Query string encoding is excluded to avoid false positives on legitimate search URLs.
// Expected: score 4, "uncertain".
runTest(
    "Tier 2 — Long URL with percent-encoded path obfuscation",
    "https://example.com/%72%65%64%69%72%65%63%74/%74%6f/evil-destination/landing-page-login"
);

// Legitimate long search URL — query string encoding should NOT trigger.
// Expected: score 0, "safe".
runTest(
    "Tier 2 — Legitimate search URL with encoded query params (no flag)",
    "https://www.google.com/search?q=hello%20world%20foo%20bar%20baz&source=hp&ei=abc123"
);

// ─── Edge cases ───────────────────────────────────────────────────────────────

// Empty string — should not throw.
// Expected: score 0, "safe".
runTest("Edge case — Empty URL", "");

// IP URL — score should cap at 10 even if other rules also fire.
// Expected: score 10, "scam".
runTest("Edge case — IP URL score cap", "http://192.0.2.1/very-long-path-that-exceeds-the-soft-threshold-and-adds-more-characters-here");
