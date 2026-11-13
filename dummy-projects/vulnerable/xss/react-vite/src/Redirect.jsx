import { useEffect } from "react";

// /?next=javascript:alert(1)  -> script runs from the navigation sink
export default function Redirect() {
  const next = new URLSearchParams(location.search).get("next");
  const back = new URLSearchParams(location.search).get("back");
  useEffect(() => {
    if (next) window.location.href = next; // VULN-EXPECTED
  }, [next]);
  return <a href={back}>Back</a>; // VULN-EXPECTED
}
