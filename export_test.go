package traefik_real_ip

import "net/http"

// ExpireEdgeSecretCacheForTest forces the next request to re-check the edge secret file.
func ExpireEdgeSecretCacheForTest(handler http.Handler) {
	resolver, ok := handler.(*IPResolver)
	if !ok || resolver.scoped == nil || resolver.scoped.edgeAuth == nil {
		return
	}

	resolver.scoped.edgeAuth.mu.Lock()
	resolver.scoped.edgeAuth.checked = resolver.scoped.edgeAuth.checked.AddDate(0, 0, -1)
	resolver.scoped.edgeAuth.mu.Unlock()
}
