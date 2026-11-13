// Server component: the secret is read server-side only, the public value is a plain URL.
export default async function Page() {
  const secret = process.env.SESSION_SECRET; // SAFE-EXPECTED
  const base = process.env.NEXT_PUBLIC_API_BASE_URL; // SAFE-EXPECTED
  return <p>{base}{secret ? " (configured)" : ""}</p>;
}
