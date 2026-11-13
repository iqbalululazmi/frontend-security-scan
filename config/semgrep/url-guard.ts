// Reference guard used by the rule tests (not a rule file).
const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);

export function assertAllowedUrl(input: string): URL {
  const url = new URL(input);
  if (url.protocol !== "https:") throw new Error("Only https is allowed");
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error("Host not allowed");
  return url;
}

export const validateTargetUrl = assertAllowedUrl;
