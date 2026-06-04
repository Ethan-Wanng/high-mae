package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalAPIHandlerBlocksCrossSiteRequests(t *testing.T) {
	handler := localAPIHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:10809/api/action", nil)
	req.Header.Set(apiRequestHeader, apiRequestHeaderValue)
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

func TestLocalAPIHandlerAllowsTrustedWebUIRequests(t *testing.T) {
	handler := localAPIHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:10809/api/action", nil)
	req.Header.Set(apiRequestHeader, apiRequestHeaderValue)
	req.Header.Set("Origin", "http://127.0.0.1:10809")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected trusted request through, got %d", rr.Code)
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
