import express from "express";
import { config } from "./config.js";

const app = express();
app.get("/health", (_req, res) => res.json({ ok: true, jwt: Boolean(config.jwtSecret) }));
app.listen(3001);
