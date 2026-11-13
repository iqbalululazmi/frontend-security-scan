"use server";

// Server action: form posts an arbitrary endpoint to "test".
export async function checkWebhook(formData: FormData) {
  const endpoint = formData.get("endpoint") as string;
  const res = await fetch(endpoint, { method: "POST" }); // VULN-EXPECTED
  return { ok: res.ok };
}
