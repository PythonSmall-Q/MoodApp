// Page-level API host override. Set this to your API origin when frontend and API are on different domains.
// Example: window.FEELINGS_API_BASE = 'https://feeling.xmoj-bbs.me';
window.FEELINGS_API_BASE = 'https://feeling.xmoj-bbs.me';

// Provide a deterministic API helper and base for other scripts to use.
try {
	// API base string (empty = same-origin)
	window.API_BASE = (window.FEELINGS_API_BASE && String(window.FEELINGS_API_BASE).replace(/\/$/, '')) || '';
	// apiUrl: returns absolute URL when FEELINGS_API_BASE set, otherwise returns the given path unchanged.
	window.apiUrl = function(path) {
		try {
			if (window.FEELINGS_API_BASE) return String(window.FEELINGS_API_BASE).replace(/\/$/, '') + path;
		} catch (e) {}
		return path;
	};
} catch (e) {}

// Monkey-patch global fetch so that any requests targeting the current origin's
// `/api/...` endpoints are transparently redirected to `FEELINGS_API_BASE` when set.
// This avoids changing every file to use the API base and fixes cross-subdomain setups
// where frontend is served from a different subdomain than the API host.
(function(){
	try {
		if (!window.FEELINGS_API_BASE) return;
		const origFetch = window.fetch.bind(window);
		const apiBaseNoSlash = String(window.FEELINGS_API_BASE).replace(/\/$/, '');
		window.fetch = function(input, init){
			try {
				// Determine URL string
				let urlStr = null;
				if (typeof input === 'string') {
					urlStr = input;
				} else if (input && input.url) {
					urlStr = input.url;
				}
				if (urlStr) {
					// Make absolute URL object using page origin as base for relative URLs
					const urlObj = new URL(urlStr, window.location.origin);
					// If this request targets the current page origin and the path starts with /api,
					// redirect it to FEELINGS_API_BASE
					if ((urlObj.origin === window.location.origin || urlStr.startsWith('/')) && urlObj.pathname.startsWith('/api')) {
						const newUrl = apiBaseNoSlash + urlObj.pathname + urlObj.search;
						if (typeof input === 'string') {
							input = newUrl;
						} else {
							// clone Request with same options
							input = new Request(newUrl, input);
						}
					}
				}
			} catch (e) {
				// fall back to original input
			}
			return origFetch(input, init);
		};
	} catch (e) {
		// no-op on failure
		console.error('api-config fetch patch failed', e);
	}
})();
