import React from "react";
import { createRoot } from "react-dom/client";
import SafeContent from "./SafeContent.jsx";

const apiBase = import.meta.env.VITE_API_BASE_URL; // SAFE-EXPECTED

function App() {
  return (
    <>
      <h1>Clean app: no SSRF, no secrets, no XSS ({String(apiBase)})</h1>
      <SafeContent comments={[{ id: 1, body: "<i>hello</i>" }]} />
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
