const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);

/** Throws unless the URL is https and its host is on the allowlist. */
export function assertAllowedUrl(input: string): URL {
  const url = new URL(input);
  if (url.protocol !== "https:") throw new Error("Only https is allowed");
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error("Host not allowed");
  return url;
}
