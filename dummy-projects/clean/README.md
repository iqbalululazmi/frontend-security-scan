# clean/

Safe counterparts of the vulnerable fixtures. **The scan must report 0 findings here.**
Lines marked `SAFE-EXPECTED` are the patterns that look risky but are fine (allowlist guards, fixed hosts,
encoded path segments, `.env.example` placeholders, server-side-only secrets, public-only `VITE_`/`NEXT_PUBLIC_` values).
