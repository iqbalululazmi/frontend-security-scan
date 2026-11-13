import { useEffect, useRef } from "react";

// /?q=<img src=x onerror=alert(1)>  -> DOM XSS through innerHTML
export default function Search() {
  const ref = useRef(null);
  const q = new URLSearchParams(window.location.search).get("q") ?? "";
  useEffect(() => {
    ref.current.innerHTML = "Results for: " + q; // VULN-EXPECTED
    document.title = q;
  }, [q]);
  return <div ref={ref} />;
}

// /?msg=<img src=x onerror=alert(1)>  -> DOM XSS through dangerouslySetInnerHTML
export function Banner() {
  const msg = new URLSearchParams(location.search).get("msg");
  return <div dangerouslySetInnerHTML={{ __html: msg }} />; // VULN-EXPECTED
}
