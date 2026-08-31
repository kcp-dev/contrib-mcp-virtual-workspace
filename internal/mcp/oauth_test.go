/*
Copyright 2026 The kcp Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func oauthOpts() OAuthOptions {
	return OAuthOptions{
		AuthorizationServers: []string{"https://idp.example.com/realms/welcome"},
	}
}

func passthrough(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
}

func TestOAuthDisabledPassesThrough(t *testing.T) {
	h := WithOAuthProtectedResource(passthrough(http.StatusTeapot), OAuthOptions{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownProtectedResource, nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("disabled middleware intercepted the request: %d", rec.Code)
	}
}

func TestWellKnownMetadata(t *testing.T) {
	h := WithOAuthProtectedResource(passthrough(http.StatusOK), oauthOpts())

	for _, path := range []string{
		WellKnownProtectedResource,
		WellKnownProtectedResource + RootPath,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "mcp.example.com"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		var md protectedResourceMetadata
		if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
			t.Fatalf("%s: bad JSON: %v", path, err)
		}
		if md.Resource != "https://mcp.example.com"+RootPath {
			t.Errorf("%s: resource %q", path, md.Resource)
		}
		if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://idp.example.com/realms/welcome" {
			t.Errorf("%s: authorization_servers %v", path, md.AuthorizationServers)
		}
	}
}

func TestWellKnownMetadataFixedResource(t *testing.T) {
	opts := oauthOpts()
	opts.Resource = "https://mcp.example.com:8443" + RootPath
	h := WithOAuthProtectedResource(passthrough(http.StatusOK), opts)

	req := httptest.NewRequest(http.MethodGet, WellKnownProtectedResource+RootPath, nil)
	req.Host = "something-else.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var md protectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md.Resource != opts.Resource {
		t.Errorf("resource %q, want %q", md.Resource, opts.Resource)
	}
}

func TestUnauthenticatedMCPRequestIsChallenged(t *testing.T) {
	h := WithOAuthProtectedResource(passthrough(http.StatusOK), oauthOpts())

	req := httptest.NewRequest(http.MethodPost, RootPath, nil)
	req.Host = "mcp.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	want := `Bearer resource_metadata="https://mcp.example.com` + WellKnownProtectedResource + RootPath + `"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate %q, want %q", got, want)
	}
}

func TestBearerRequestReachesChain(t *testing.T) {
	h := WithOAuthProtectedResource(passthrough(http.StatusOK), oauthOpts())

	req := httptest.NewRequest(http.MethodPost, RootPath, nil)
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}

func TestDownstream401GetsHint(t *testing.T) {
	h := WithOAuthProtectedResource(passthrough(http.StatusUnauthorized), oauthOpts())

	req := httptest.NewRequest(http.MethodPost, RootPath, nil)
	req.Host = "mcp.example.com"
	req.Header.Set("Authorization", "Bearer expired")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata=") {
		t.Errorf("WWW-Authenticate %q lacks resource_metadata", got)
	}
}

func TestNonMCPPathsUntouched(t *testing.T) {
	h := WithOAuthProtectedResource(passthrough(http.StatusUnauthorized), oauthOpts())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("non-MCP path got a challenge: %q", got)
	}
}
