import React from "react";
import { useEffect, useRef } from "react";
import DOMPurify from "dompurify";

// Only http(s) URLs pass; everything else (javascript:, data:) becomes "#".
function safeHref(url) {
  try {
    const u = new URL(url, window.location.origin);
    return ["http:", "https:"].includes(u.protocol) ? u.href : "#";
  } catch {
    return "#";
  }
}

export default function SafeContent({ comments }) {
  const ref = useRef(null);
  const q = new URLSearchParams(window.location.search).get("q") ?? "";
  const next = new URLSearchParams(window.location.search).get("next") ?? "/";

  useEffect(() => {
    ref.current.textContent = "Results for: " + q; // SAFE-EXPECTED
    const box = document.getElementById("root");
    box.dataset.query = q; // SAFE-EXPECTED
  }, [q]);

  const text = <p>{q}</p>; // SAFE-EXPECTED
  const link = <a href={safeHref(next)}>continue</a>; // SAFE-EXPECTED
  const fixed = <a href="https://example.com/help">Help</a>; // SAFE-EXPECTED
  const literal = <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />; // SAFE-EXPECTED
  const cleaned = comments.map((c) => (
    <p key={c.id} dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(c.body) }} /> // SAFE-EXPECTED
  ));

  return (
    <div>
      <p ref={ref} />
      {text}
      {link}
      {fixed}
      {literal}
      {cleaned}
    </div>
  );
}
