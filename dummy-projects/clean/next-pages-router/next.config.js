/** @type {import('next').NextConfig} */
module.exports = {
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "cdn.example.com" }, // SAFE-EXPECTED
      { protocol: "https", hostname: "images.example.com" },
    ],
  },
};
