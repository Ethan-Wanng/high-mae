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
