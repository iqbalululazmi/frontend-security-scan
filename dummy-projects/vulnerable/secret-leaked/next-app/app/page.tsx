"use client";

export default function Page() {
  const secret = process.env.NEXT_PUBLIC_API_SECRET; // VULN-EXPECTED
  return <button onClick={() => fetch("/api/data", { headers: { "x-api-secret": secret ?? "" } })}>Load</button>;
}
