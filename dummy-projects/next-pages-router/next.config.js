/** @type {import('next').NextConfig} */
module.exports = {
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "cdn.example.com" },
      { protocol: "https", hostname: "**" }, // VULN-EXPECTED
    ],
  },
};
