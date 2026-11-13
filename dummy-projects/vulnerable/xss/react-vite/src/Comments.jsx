// Stored XSS: comment bodies come from the API and are rendered as raw HTML (review rule).
export default function Comments({ comments }) {
  const items = comments.map((c) => <p key={c.id} dangerouslySetInnerHTML={{ __html: c.body }} />); // VULN-EXPECTED
  return items;
}
