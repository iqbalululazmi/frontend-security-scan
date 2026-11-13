import React from "react";
import { createRoot } from "react-dom/client";

function App() {
  return <h1>Clean app: no SSRF here</h1>;
}

createRoot(document.getElementById("root")).render(<App />);
