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
	"strings"

	"k8s.io/apiserver/pkg/endpoints/responsewriter"
)

// WellKnownProtectedResource is the RFC 9728 well-known prefix under which
// protected resource metadata is served.
const WellKnownProtectedResource = "/.well-known/oauth-protected-resource"

// OAuthOptions configures the OAuth 2.0 protected-resource surface (RFC 9728)
// that MCP clients use to discover how to obtain a token. The feature is off
// unless at least one authorization server is configured; everything else
// about the server is unchanged by it.
type OAuthOptions struct {
	// AuthorizationServers lists the issuer URLs advertised in the
	// protected-resource metadata. Non-empty enables the feature.
	AuthorizationServers []string

	// Resource is the canonical resource identifier advertised in the
	// metadata and used in WWW-Authenticate hints. Empty derives it from
	// each request's Host header, which keeps one deployment correct behind
	// any proxy or gateway that preserves the external Host.
	Resource string

	// ScopesSupported optionally lists scopes clients should request.
	ScopesSupported []string
}

// Enabled reports whether the protected-resource surface is configured.
func (o OAuthOptions) Enabled() bool {
	return len(o.AuthorizationServers) > 0
}

type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func (o OAuthOptions) resourceFor(r *http.Request) string {
	if o.Resource != "" {
		return o.Resource
	}
	return "https://" + r.Host + RootPath
}

func (o OAuthOptions) metadataURLFor(r *http.Request) string {
	if o.Resource != "" {
		if i := strings.Index(o.Resource, "://"); i >= 0 {
			if j := strings.Index(o.Resource[i+3:], "/"); j >= 0 {
				origin := o.Resource[:i+3+j]
				path := o.Resource[i+3+j:]
				return origin + WellKnownProtectedResource + path
			}
		}
		return o.Resource + WellKnownProtectedResource
	}
	return "https://" + r.Host + WellKnownProtectedResource + RootPath
}

func (o OAuthOptions) serveMetadata(w http.ResponseWriter, r *http.Request) {
	md := protectedResourceMetadata{
		Resource:               o.resourceFor(r),
		AuthorizationServers:   o.AuthorizationServers,
		ScopesSupported:        o.ScopesSupported,
		BearerMethodsSupported: []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(md)
}

func (o OAuthOptions) challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate",
		`Bearer resource_metadata="`+o.metadataURLFor(r)+`"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// WithOAuthProtectedResource wraps handler with the protected-resource
// discovery surface
func WithOAuthProtectedResource(handler http.Handler, o OAuthOptions) http.Handler {
	if !o.Enabled() {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownProtectedResource ||
			strings.HasPrefix(r.URL.Path, WellKnownProtectedResource+"/") {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			o.serveMetadata(w, r)
			return
		}

		mcpPath := r.URL.Path == RootPath || strings.HasPrefix(r.URL.Path, RootPath+"/")
		if mcpPath && r.Header.Get("Authorization") == "" &&
			(r.TLS == nil || len(r.TLS.PeerCertificates) == 0) {
			o.challenge(w, r)
			return
		}

		if mcpPath {
			// WrapForHTTP1Or2 keeps the writer's CloseNotifier/Flusher/
			// Hijacker surface intact; downstream filters and the MCP SDK
			// type-assert these and panic on a bare decorator.
			injector := responsewriter.WrapForHTTP1Or2(&challengeInjector{ResponseWriter: w, opts: o, req: r})
			handler.ServeHTTP(injector, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// challengeInjector adds the WWW-Authenticate hint to any 401 written by the
// wrapped chain for MCP requests, without otherwise altering the response.
type challengeInjector struct {
	http.ResponseWriter
	opts OAuthOptions
	req  *http.Request
}

func (c *challengeInjector) WriteHeader(status int) {
	if status == http.StatusUnauthorized && c.Header().Get("WWW-Authenticate") == "" {
		c.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="`+c.opts.metadataURLFor(c.req)+`"`)
	}
	c.ResponseWriter.WriteHeader(status)
}

// Flush keeps SSE streaming working through the wrapper; MCP's streamable
// HTTP transport depends on it.
func (c *challengeInjector) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the inner writer, satisfying responsewriter.UserProvidedDecorator.
func (c *challengeInjector) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}
