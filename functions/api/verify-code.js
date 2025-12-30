// functions/api/verify-code.js
export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();
    const full_name = String(body.full_name || "").trim(); // ✅ DEFINE IT
    const password = String(body.password || "").trim();
    const company_name = String(body.company_name || "").trim();

    if (!email) return json({ ok: false, error: "Missing email" }, 400);
    if (!code) return json({ ok: false, error: "Missing code" }, 400);
    if (!full_name) return json({ ok: false, error: "Missing full_name" }, 400);
    if (!password) return json({ ok: false, error: "Missing password" }, 400);
    if (!company_name) return json({ ok: false, error: "Missing company_name" }, 400);

    if (!env.SUPABASE_URL) return json({ ok: false, error: "Missing SUPABASE_URL env var" }, 500);
    if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ ok: false, error: "Missing SUPABASE_SERVICE_ROLE_KEY env var" }, 500);
    if (!env.CODE_SALT) return json({ ok: false, error: "Missing CODE_SALT env var" }, 500);

    // 1) Hash the code the same way send-code.js does
    const enc = new TextEncoder();
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(code + env.CODE_SALT));
    const code_hash = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");

    // 2) Find a valid, un-used signup code row
    const query = new URL(`${env.SUPABASE_URL}/rest/v1/signup_codes`);
    query.searchParams.set("select", "id,email,expires_at,used_at,purpose,company_code");
    query.searchParams.set("email", `eq.${email}`);
    query.searchParams.set("code_hash", `eq.${code_hash}`);
    query.searchParams.set("order", "created_at.desc");
    query.searchParams.set("limit", "1");

    const codeRes = await fetch(query.toString(), {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });

    const rows = await codeRes.json().catch(() => []);
    const row = rows?.[0];

    if (!row) return json({ ok: false, error: "Invalid code" }, 400);
    if (row.used_at) return json({ ok: false, error: "Code already used" }, 400);
    if (new Date(row.expires_at).getTime() < Date.now()) return json({ ok: false, error: "Code expired" }, 400);

    // 3) Create user via Supabase Admin API (service role)
    const createUserRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name },
      }),
    });

    const created = await createUserRes.json().catch(() => ({}));
    const userId = created?.id;

    if (!createUserRes.ok || !userId) {
      return json(
        { ok: false, error: "Create user failed", details: created },
        500
      );
    }

    // 4) Mark the code as used
    await fetch(`${env.SUPABASE_URL}/rest/v1/signup_codes?id=eq.${row.id}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=minimal",
      },
      body: JSON.stringify({ used_at: new Date().toISOString(), used_by: userId }),
    });

    // 5) (Optional) Create company record (only for owner signup)
    // NOTE: Your companies table must have owner_user_id uuid referencing auth.users(id)
    if ((row.purpose || "owner_signup") === "owner_signup") {
      const insCompany = await fetch(`${env.SUPABASE_URL}/rest/v1/companies`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          prefer: "return=representation",
        },
        body: JSON.stringify([{
          company_name,
          owner_user_id: userId,
        }]),
      });

      const comp = await insCompany.json().catch(() => ({}));
      if (!insCompany.ok) {
        return json({ ok: false, error: "Create company failed", details: comp }, 500);
      }
    }

    return json({ ok: true, user_id: userId });

  } catch (e) {
    return json({ ok: false, error: e?.message || String(e) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
