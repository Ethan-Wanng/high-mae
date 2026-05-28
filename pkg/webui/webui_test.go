package webui

import "testing"

func TestEvaluateSiteAccessDetectsGeminiRegionUnsupported(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_gemini",
		Name:     "Gemini",
		Category: "AI",
		URL:      "https://gemini.google.com/",
		Preset:   true,
	}

	ok, msg := evaluateSiteAccess(target, 200, "Gemini目前不支持你所在的地区。敬请期待！")
	if ok {
		t.Fatalf("expected Gemini region unsupported page to fail, got ok with %q", msg)
	}
	if msg != "地区不支持" {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestEvaluateSiteAccessAllowsChatGPTProbeChallenge(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_chatgpt",
		Name:     "ChatGPT",
		Category: "AI",
		URL:      "https://chatgpt.com/",
		Preset:   true,
	}

	ok, msg := evaluateSiteAccess(target, 403, "Just a moment...")
	if !ok {
		t.Fatalf("expected ChatGPT challenge response to be treated as reachable, got %q", msg)
	}
}

func TestEvaluateSiteAccessDetectsChatGPTRegionUnsupported(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_chatgpt",
		Name:     "ChatGPT",
		Category: "AI",
		URL:      "https://chatgpt.com/",
		Preset:   true,
	}

	ok, msg := evaluateSiteAccess(target, 200, "OpenAI's services are not available in your country.")
	if ok {
		t.Fatalf("expected ChatGPT region unsupported page to fail, got ok with %q", msg)
	}
}

func TestShouldRetryGeminiProbeOnAmbiguousFailure(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_gemini",
		Name:     "Gemini",
		Category: "AI",
		URL:      "https://gemini.google.com/",
		Preset:   true,
	}
	result := SiteTestResult{StatusCode: 503, OK: false}

	if !shouldRetryGeminiProbe(target, result, "temporary error", "https://gemini.google.com/_/BardChatUi/") {
		t.Fatal("expected ambiguous Gemini failure to retry fallback probe")
	}
	if shouldRetryGeminiProbe(target, result, "Gemini目前不支持你所在的地区。", "https://gemini.google.com/_/BardChatUi/") {
		t.Fatal("did not expect explicit region unsupported page to retry fallback probe")
	}
}

func TestPresetSiteTargetsDoNotIncludeReuters(t *testing.T) {
	for _, target := range presetSiteTargets {
		if target.ID == "preset_reuters" || target.URL == "https://www.reuters.com/" {
			t.Fatalf("Reuters should not be a preset target: %+v", target)
		}
	}
}
