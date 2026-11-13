import express from "express";

const app = express();
app.use(express.json());

// res.send(string) responds as text/html, so request data in the string is reflected XSS.

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>"); // VULN-EXPECTED
});

app.get("/items/:id", (req, res) => {
  res.status(404).send(`<p>Item ${req.params.id} not found</p>`); // VULN-EXPECTED
});

app.get("/search", (req, res) => {
  res.write("<p>Results for " + req.query.q + "</p>"); // VULN-EXPECTED
  res.end();
});

app.post("/preview", (req, res) => {
  res.type("html").send(req.body.html); // VULN-EXPECTED
});

app.use((req, res) => {
  res.status(404).send(`<h1>Not found: ${req.originalUrl}</h1>`); // VULN-EXPECTED
});

app.listen(3004);
