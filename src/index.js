const supportedProviders = ['github', 'gitlab'];

const providerScopes = {
github: { default: 'repo,user', separator: ',', allowed: ['repo', 'public_repo', 'user', 'read:user', 'user:email'] },
gitlab: { default: 'api', separator: ' ', allowed: ['api', 'read_api', 'read_user', 'read_repository', 'write_repository'] },
};

const getScope = (provider, requested) => {
const { default: fallback, separator, allowed } = providerScopes[provider];
const scopes = (requested ?? '').split(/[\s,]+/).filter(Boolean);
if (!scopes.length) return fallback;
if (scopes.every((scope) => allowed.includes(scope))) return scopes.join(separator);
console.warn(`Ignoring the unsupported "${requested}" scope for ${provider}; requesting "${fallback}".`);
return fallback;
};

const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getDomainPatterns = (allowedDomains) => (allowedDomains ?? '').split(/,/).map((str) => str.trim()).filter(Boolean).map((str) => `^${escapeRegExp(str).replaceAll('\\*', '.+')}$`);

const serialize = (value) => JSON.stringify(value ?? null).replaceAll('<', '\\u003c');

const outputHTML = ({ provider = 'unknown', token, error, errorCode, env = {} }) => {
const state = error ? 'error' : 'success';
const content = error ? { provider, error, errorCode } : { provider, token };
return new Response(`<!doctype html><html><body><script>
(() => {
const trustedPatterns = ${serialize(getDomainPatterns(env.ALLOWED_DOMAINS))};
const hasToken = ${serialize(!!token)};
const isTrusted = (origin) => {
try {
const { hostname } = new URL(origin);
return trustedPatterns.some((pattern) => new RegExp(pattern).test(hostname));
} catch {
return false;
}
};
window.addEventListener('message', ({ data, origin }) => {
if (data !== 'authorizing:${provider}') return;
if (hasToken && trustedPatterns.length && !isTrusted(origin)) return;
window.opener?.postMessage('authorization:${provider}:${state}:${JSON.stringify(content)}', origin);
});
window.opener?.postMessage('authorizing:${provider}', '*');
})();
</script></body></html>`, {
headers: {
'Content-Type': 'text/html;charset=UTF-8',
'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure`,
},
});
};

const handleAuth = async (request, env) => {
const { url } = request;
const { origin, searchParams } = new URL(url);
const { provider, site_id: domain, scope: requestedScope } = Object.fromEntries(searchParams);
if (!provider || !supportedProviders.includes(provider)) {
return outputHTML({ env, error: 'Your Git backend is not supported by the authenticator.', errorCode: 'UNSUPPORTED_BACKEND' });
}
const scope = getScope(provider, requestedScope);
const { ALLOWED_DOMAINS, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_HOSTNAME = 'github.com', GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET, GITLAB_HOSTNAME = 'gitlab.com' } = env;
const domainPatterns = getDomainPatterns(ALLOWED_DOMAINS);
if (domainPatterns.length && !domainPatterns.some((pattern) => new RegExp(pattern).test(domain ?? ''))) {
return outputHTML({ env, provider, error: 'Your domain is not allowed to use the authenticator.', errorCode: 'UNSUPPORTED_DOMAIN' });
}
const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');
let authURL = '';
if (provider === 'github') {
if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
return outputHTML({ env, provider, error: 'OAuth app client ID or secret is not configured.', errorCode: 'MISCONFIGURED_CLIENT' });
}
const params = new URLSearchParams({ client_id: GITHUB_CLIENT_ID, scope, state: csrfToken });
authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;
}
if (provider === 'gitlab') {
if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
return outputHTML({ env, provider, error: 'OAuth app client ID or secret is not configured.', errorCode: 'MISCONFIGURED_CLIENT' });
}
const params = new URLSearchParams({ client_id: GITLAB_CLIENT_ID, redirect_uri: `${origin}/callback`, response_type: 'code', scope, state: csrfToken });
authURL = `https://${GITLAB_HOSTNAME}/oauth/authorize?${params.toString()}`;
}
return new Response('', {
status: 302,
headers: {
Location: authURL,
'Set-Cookie': `csrf-token=${provider}_${csrfToken}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
},
});
};

const handleCallback = async (request, env) => {
const { url, headers } = request;
const { origin, searchParams } = new URL(url);
const { code, state } = Object.fromEntries(searchParams);
const [, provider, csrfToken] = headers.get('Cookie')?.match(/\bcsrf-token=([a-z-]+?)_([0-9a-f]{32})\b/) ?? [];
if (!provider || !supportedProviders.includes(provider)) {
return outputHTML({ env, error: 'Your Git backend is not supported by the authenticator.', errorCode: 'UNSUPPORTED_BACKEND' });
}
if (!code || !state) {
return outputHTML({ env, provider, error: 'Failed to receive an authorization code. Please try again later.', errorCode: 'AUTH_CODE_REQUEST_FAILED' });
}
if (!csrfToken || state !== csrfToken) {
return outputHTML({ env, provider, error: 'Potential CSRF attack detected. Authentication flow aborted.', errorCode: 'CSRF_DETECTED' });
}
const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_HOSTNAME = 'github.com', GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET, GITLAB_HOSTNAME = 'gitlab.com' } = env;
let tokenURL = '';
let requestBody = {};
if (provider === 'github') {
if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
return outputHTML({ env, provider, error: 'OAuth app client ID or secret is not configured.', errorCode: 'MISCONFIGURED_CLIENT' });
}
tokenURL = `https://${GITHUB_HOSTNAME}/login/oauth/access_token`;
requestBody = { code, client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET };
}
if (provider === 'gitlab') {
if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
return outputHTML({ env, provider, error: 'OAuth app client ID or secret is not configured.', errorCode: 'MISCONFIGURED_CLIENT' });
}
tokenURL = `https://${GITLAB_HOSTNAME}/oauth/token`;
requestBody = { code, client_id: GITLAB_CLIENT_ID, client_secret: GITLAB_CLIENT_SECRET, grant_type: 'authorization_code', redirect_uri: `${origin}/callback` };
}
let response;
let token = '';
let error = '';
try {
response = await fetch(tokenURL, {
method: 'POST',
headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
body: JSON.stringify(requestBody),
});
} catch {
}
if (!response) {
return outputHTML({ env, provider, error: 'Failed to request an access token. Please try again later.', errorCode: 'TOKEN_REQUEST_FAILED' });
}
try {
({ access_token: token, error } = await response.json());
} catch {
return outputHTML({ env, provider, error: 'Server responded with malformed data. Please try again later.', errorCode: 'MALFORMED_RESPONSE' });
}
return outputHTML({ env, provider, token, error });
};

export default {
async fetch(request, env) {
const { method, url } = request;
const { pathname } = new URL(url);
if (method === 'GET' && ['/auth', '/oauth/authorize'].includes(pathname)) {
return handleAuth(request, env);
}
if (method === 'GET' && ['/callback', '/oauth/redirect'].includes(pathname)) {
return handleCallback(request, env);
}
return new Response('', { status: 404 });
},
};
