// Rule tests for xss-sinks.yml. Run: python3 scan.py self-test
// "ruleid" = must be reported on the next line, "ok" = must NOT be reported.
import DOMPurify from "dompurify";
import { escapeHtml } from "./html";

declare const app: any;
declare const useSearchParams: any;
declare function safeHref(u: string): string;

// ------------------------------ DOM sinks (client) ------------------------------
function domSinks(el: HTMLElement) {
  // ruleid: xss-dom-sink-tainted
  el.innerHTML = location.hash.slice(1);

  const q = new URLSearchParams(window.location.search).get("q") ?? "";
  // ruleid: xss-dom-sink-tainted
  el.insertAdjacentHTML("beforeend", q);

  // ruleid: xss-dom-sink-tainted
  document.write(document.referrer);

  // ruleid: xss-dom-sink-tainted
  window.location.href = q;

  // ruleid: xss-dom-sink-tainted
  location.assign(new URLSearchParams(location.search).get("next")!);

  // ruleid: xss-dom-sink-tainted
  el.outerHTML = localStorage.getItem("bio")!;
}

window.addEventListener("message", (e) => {
  const box = document.getElementById("box")!;
  // ruleid: xss-dom-sink-tainted
  box.innerHTML = e.data;
});

export function ReactSinks() {
  const [params] = useSearchParams();
  const html = params.get("html");
  const next = new URLSearchParams(location.search).get("next");
  // ruleid: xss-dom-sink-tainted
  const el1 = <div dangerouslySetInnerHTML={{ __html: html }} />;
  // ruleid: xss-dom-sink-tainted
  const el2 = <a href={next}>continue</a>;
  return [el1, el2];
}

export default async function Page({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const { q } = await searchParams;
  // ruleid: xss-dom-sink-tainted
  return <div dangerouslySetInnerHTML={{ __html: q! }} />;
}

// ----------------------------- safe look-alikes -----------------------------
function domSafe(el: HTMLElement) {
  // ok: xss-dom-sink-tainted
  el.textContent = location.hash.slice(1);

  // ok: xss-dom-sink-tainted
  el.innerHTML = DOMPurify.sanitize(location.hash.slice(1));

  // ok: xss-dom-sink-tainted
  el.innerHTML = "<b>static</b>";

  const q = new URLSearchParams(location.search).get("q") ?? "";
  // ok: xss-dom-sink-tainted
  window.location.href = "/search?q=" + encodeURIComponent(q);

  // ok: xss-dom-sink-tainted
  location.assign(safeHref(q));

  const page = Number(new URLSearchParams(location.search).get("page"));
  // ok: xss-dom-sink-tainted
  el.innerHTML = `<p>page ${page}</p>`;
}

export function ReactSafe({ title }: { title: string }) {
  const q = new URLSearchParams(location.search).get("q") ?? "";
  // ok: xss-dom-sink-tainted
  const el1 = <p>{q}</p>;
  // ok: xss-dom-sink-tainted
  const el2 = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(q) }} />;
  // ok: xss-dom-sink-tainted
  const el3 = <a href={safeHref(q)}>go</a>;
  // ok: xss-dom-sink-tainted
  const el4 = <a href="https://example.com">fixed</a>;
  // ok: xss-dom-sink-tainted
  const el5 = <h1>{title}</h1>;
  return [el1, el2, el3, el4, el5];
}

// ------------------------------ reflected (server) ------------------------------
app.get("/hello", (req: any, res: any) => {
  // ruleid: xss-reflected-server-response
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.get("/items/:id", (req: any, res: any) => {
  // ruleid: xss-reflected-server-response
  res.status(404).send(`<p>${req.params.id} not found</p>`);
});

app.post("/render", (req: any, res: any) => {
  // ruleid: xss-reflected-server-response
  res.type("html").send(req.body.html);
});

app.get("/stream", (req: any, res: any) => {
  const { msg } = req.query;
  // ruleid: xss-reflected-server-response
  res.write("<p>" + msg + "</p>");
  res.end();
});

export async function GET(request: Request) {
  const name = new URL(request.url).searchParams.get("name");
  // ruleid: xss-reflected-server-response
  return new Response(`<h1>${request.url}</h1>`, { headers: { "content-type": "text/html" } });
}

app.get("/ok-escaped", (req: any, res: any) => {
  // ok: xss-reflected-server-response
  res.send("<h1>Hello " + escapeHtml(String(req.query.name)) + "</h1>");
});

app.get("/ok-json", (req: any, res: any) => {
  // ok: xss-reflected-server-response
  res.json({ name: req.query.name });
});

app.get("/ok-object", (req: any, res: any) => {
  // ok: xss-reflected-server-response
  res.send({ name: req.query.name });
});

app.get("/ok-text", (req: any, res: any) => {
  // ok: xss-reflected-server-response
  res.type("text/plain").send(req.query.name);
});

app.get("/ok-proxy", async (req: any, res: any) => {
  // Not direct reflection: the body comes from a fetched URL (reported by the SSRF rule instead).
  const r = await fetch(req.query.url);
  // ok: xss-reflected-server-response
  res.send(await r.text());
});

app.get("/ok-static", (req: any, res: any) => {
  // ok: xss-reflected-server-response
  res.send("<h1>Welcome</h1>");
});

export async function POST(request: Request) {
  const body = await request.json();
  // ok: xss-reflected-server-response
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
}

// ------------------------------------ eval ------------------------------------
function evals(code: string, cb: string) {
  // ruleid: xss-eval-like
  eval(code);
  // ruleid: xss-eval-like
  new Function("a", code);
  // ruleid: xss-eval-like
  setTimeout("run(" + cb + ")", 10);
  // ok: xss-eval-like
  eval("1 + 1");
  // ok: xss-eval-like
  setTimeout(() => console.log("x"), 10);
  // ok: xss-eval-like
  setTimeout(handler, 10);
  // ok: xss-eval-like
  setInterval("tick()", 1000);
}
declare function handler(): void;

// ------------------------------- javascript: URLs -------------------------------
export function JsUrls() {
  // ruleid: xss-javascript-url-literal
  const el1 = <a href="javascript:alert(1)">click</a>;
  // ok: xss-javascript-url-literal
  const el2 = <a href="https://example.com">fine</a>;
  // ok: xss-javascript-url-literal
  const el3 = <a href="/about">fine</a>;
  return [el1, el2, el3];
}
