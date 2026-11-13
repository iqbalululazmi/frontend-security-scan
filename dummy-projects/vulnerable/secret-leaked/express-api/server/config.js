// All values are fake. Every leaking line is flagged on purpose.
export const config = {
  jwtSecret: "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c", // VULN-EXPECTED
};

export const signingKey =
  "-----BEGIN RSA PRIVATE KEY-----\n" + // VULN-EXPECTED
  "MIIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n" +
  "-----END RSA PRIVATE KEY-----\n";
