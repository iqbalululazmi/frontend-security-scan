// Server component: /preview?url=https://site.example  -> renders the page title
export default async function PreviewPage({
  searchParams,
}: {
  searchParams: Promise<{ url?: string }>;
}) {
  const { url } = await searchParams;
  if (!url) return <p>Pass ?url=</p>;

  const res = await fetch(url); // VULN-EXPECTED
  const html = await res.text();
  const title = html.match(/<title>(.*?)<\/title>/i)?.[1] ?? "(no title)";
  return <h1>{title}</h1>;
}
