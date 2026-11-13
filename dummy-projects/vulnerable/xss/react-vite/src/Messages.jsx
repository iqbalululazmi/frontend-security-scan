import { useEffect } from "react";

export default function Messages() {
  useEffect(() => {
    // Any window can postMessage here, and the payload goes straight into the DOM as HTML.
    window.addEventListener("message", (e) => {
      document.getElementById("inbox").insertAdjacentHTML("beforeend", e.data); // VULN-EXPECTED
    });
    document.write(document.referrer); // VULN-EXPECTED
  }, []);
  return null;
}

// Legacy widget loader: executes whatever the callback parameter says.
export function runCallback(code) {
  eval(code); // VULN-EXPECTED
}

export function HelpLink() {
  return <a href="javascript:alert(document.domain)">Help</a>; // VULN-EXPECTED
}
