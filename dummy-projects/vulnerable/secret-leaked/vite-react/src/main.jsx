import React from "react";
import { createRoot } from "react-dom/client";

const token = import.meta.env.VITE_ADMIN_TOKEN; // VULN-EXPECTED

createRoot(document.getElementById("root")).render(<h1>admin token length: {String(token).length}</h1>);
