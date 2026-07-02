package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalAPIHandlerBlocksCrossSiteRequests(t *testing.T) {
	handler := localAPIHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:10809/api/action", nil)
	req.Header.Set(apiRequestHeader, apiRequestHeaderValue)
	req.Header.Set(apiRequestTokenHeader, apiRequestToken)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected cross-site request to be blocked, got %d", rr.Code)
	}
}

func TestLocalAPIHandlerRequiresWebUIHeader(t *testing.T) {
	handler := localAPIHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:10809/api/action", nil)
	req.Header.Set("Origin", "http://127.0.0.1:10809")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected missing API header to be blocked, got %d", rr.Code)
	}
}

func TestLocalAPIHandlerRequiresWebUIToken(t *testing.T) {
	handler := localAPIHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:10809/api/action", nil)
	req.Header.Set(apiRequestHeader, apiRequestHeaderValue)
	req.Header.Set("Origin", "http://127.0.0.1:10809")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected missing API token to be blocked, got %d", rr.Code)
	}
}

func TestHealthEndpointDoesNotRequireAPIToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:10809/healthz", nil)
	rr := httptest.NewRecorder()

	serveHealth(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected health endpoint without API token to return 204, got %d", rr.Code)
	}
}

func TestLocalAPIHandlerAllowsTrustedWebUIRequests(t *testing.T) {
	handler := localAPIHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:10809/api/action", nil)
	req.Header.Set(apiRequestHeader, apiRequestHeaderValue)
	req.Header.Set(apiRequestTokenHeader, apiRequestToken)
	req.Header.Set("Origin", "http://127.0.0.1:10809")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected trusted request through, got %d", rr.Code)
	}
}

func TestRenderIndexHTMLInjectsAPIToken(t *testing.T) {
	page := renderIndexHTML()
	if !strings.Contains(page, `name="wing-api-token"`) || !strings.Contains(page, apiRequestToken) {
		t.Fatal("expected rendered WebUI HTML to include API token meta tag")
	}
}

func TestTrustedWebUIOriginAllowsLocalAndPrivateHosts(t *testing.T) {
	origins := []string{
		"http://127.0.0.1:10809",
		"http://localhost:10809",
		"http://10.0.2.2:10809",
		"http://192.168.1.8:10809",
	}

	for _, origin := range origins {
		if !isTrustedWebUIOrigin(origin) {
			t.Fatalf("expected %s to be trusted", origin)
		}
	}
}

func TestTrustedWebUIOriginRejectsPublicHosts(t *testing.T) {
	origins := []string{
		"https://evil.example",
		"http://8.8.8.8:10809",
	}

	for _, origin := range origins {
		if isTrustedWebUIOrigin(origin) {
			t.Fatalf("expected %s to be rejected", origin)
		}
	}
}

func TestManagedAggregateGroupFileName(t *testing.T) {
	allowed := []string{
		"group_1710000000.yml",
		"agg_1710000000.yml",
	}
	for _, fileName := range allowed {
		if !isManagedAggregateGroupFileName(fileName) {
			t.Fatalf("expected %s to be a managed aggregate group file", fileName)
		}
	}

	blocked := []string{
		"",
		"nodes.yml",
		"../nodes.yml",
		`..\nodes.yml`,
		"group_1710000000.json",
		"C:/Users/name/nodes.yml",
	}
	for _, fileName := range blocked {
		if isManagedAggregateGroupFileName(fileName) {
			t.Fatalf("expected %s to be rejected", fileName)
		}
	}
}
