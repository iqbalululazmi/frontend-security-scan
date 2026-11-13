import { useState } from "react";

// Browser code. Calling fetch() with user input here is not SSRF (no server-side request);
// the scanner must NOT report it.
export default function App() {
  const [url, setUrl] = useState("");
  const [body, setBody] = useState("");

  async function load() {
    const res = await fetch(`/api/safe-proxy?url=${encodeURIComponent(url)}`); // SAFE-EXPECTED
    setBody(await res.text());
  }

  async function loadDirect() {
    const res = await fetch(url); // SAFE-EXPECTED
    setBody(await res.text());
  }

  return (
    <div>
      <input value={url} onChange={(e) => setUrl(e.target.value)} />
      <button onClick={load}>Load via BFF</button>
      <button onClick={loadDirect}>Load direct</button>
      <pre>{body}</pre>
    </div>
  );
}
