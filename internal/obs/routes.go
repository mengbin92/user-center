package obs

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/mux"
)

// MethodAny registers a template for every method. Raw handlers do their own
// method checks, and the route table must not pretend otherwise.
const MethodAny = "*"

// RouteSet is the closed set of route templates this process actually serves.
//
// It exists because a metric label must never be derived from the request URL.
// The outer HTTP filter (where the counter is recorded) runs before the router,
// so the transport's path template is not available there: the previous
// fallback masked numeric segments of the raw path, which still let
// /api/v1/admin/users/{name}:archive produce one series per user and let any
// unauthenticated caller mint unbounded series by requesting random URLs. Both
// are cardinality attacks, and the first also leaks identifiers into the scrape.
//
// The set is populated from the real router (Kratos Server.WalkRoute for the
// protobuf routes, explicit Add for the raw handlers) and is read-only
// afterwards, so a path that is not in it cannot become a label.
type RouteSet struct {
	mu     sync.RWMutex
	router *mux.Router
	seen   map[string]struct{}
}

// NewRouteSet returns an empty set. It is safe to Add before serving and to
// Match concurrently once serving starts.
func NewRouteSet() *RouteSet {
	return &RouteSet{router: mux.NewRouter(), seen: make(map[string]struct{})}
}

// Add registers one (method, template) pair using the same template syntax as
// the real router ({id}, {provider}, {id}:action). Duplicates are ignored so a
// template can be reached through both WalkRoute and an explicit registration.
//
// The method is part of the key on purpose: the router itself registers
// GET /api/v1/admin/users/{id} and POST /api/v1/admin/users/{id}:archive
// separately, and without the method the GET template would swallow the archive
// path (`{id}` matches "4242:archive") and label it as a plain read.
//
// An invalid template panics: that is a startup bug in the route table, and
// failing loudly is better than silently dropping the route and reporting its
// traffic as "unknown" forever.
func (s *RouteSet) Add(method, template string) {
	if s == nil || template == "" {
		return
	}
	if method == "" {
		method = MethodAny
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := method + " " + template
	if _, ok := s.seen[key]; ok {
		return
	}
	s.seen[key] = struct{}{}
	route := s.router.NewRoute().Path(template)
	if method != MethodAny {
		route.Methods(method)
	}
}

// Len reports how many templates are registered. Used by tests and by the
// startup log line so an operator can see that the table was populated.
func (s *RouteSet) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.seen)
}

// Match maps a concrete request onto its registered template. The returned
// template is the router's own path template, so it is identical to what the
// router matched — including action suffixes such as {id}:archive.
func (s *RouteSet) Match(method, path string) (string, bool) {
	if s == nil || path == "" {
		return "", false
	}
	if method == "" {
		method = http.MethodGet
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.seen) == 0 {
		return "", false
	}
	var match mux.RouteMatch
	if !s.router.Match(&http.Request{Method: method, URL: &url.URL{Path: path}}, &match) {
		return "", false
	}
	if match.Route == nil {
		return "", false
	}
	template, err := match.Route.GetPathTemplate()
	if err != nil || template == "" {
		return "", false
	}
	return template, true
}
