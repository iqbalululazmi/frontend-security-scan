// Rule tests for xss-review.yml. Run: python3 scan.py self-test
import DOMPurify from "dompurify";

declare const comment: { body: string };

export function Review({ html }: { html: string }) {
  // ruleid: xss-react-dangerously-set-inner-html
  const el1 = <p dangerouslySetInnerHTML={{ __html: comment.body }} />;
  // ruleid: xss-react-dangerously-set-inner-html
  const el2 = <p dangerouslySetInnerHTML={{ __html: html }} />;
  // ok: xss-react-dangerously-set-inner-html
  const el3 = <p dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
  // ok: xss-react-dangerously-set-inner-html
  const el4 = <p dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;
  return [el1, el2, el3, el4];
}
