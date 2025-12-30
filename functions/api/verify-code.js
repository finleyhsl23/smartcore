export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const purpose = String(body.purpose || "owner_signup").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();
    const full_name = String(body.full_name || "").trim();
    const password = String(body.password || "");
    const company_name = String(body.company_name || "").trim();
    const company_size = String(body.company_size || "").trim();
    const module_ids = Array.isArray(body.module_ids) ? body.module_ids.map(String) : [];

    if (!env.SUPABASE_URL) return jsonErr("Missing SUPABASE_URL env var", 500);
    if (!env.SUPABASE_SERVICE_ROLE_KEY) return jsonErr("Missing SUPABASE_SERVICE_ROLE_KEY env var", 500);
    if (!env.CODE_SALT) return jsonErr("Missing CODE_SALT env var", 500);

    if (!email) return jsonErr("Missing email", 400);
    if (!code || code.length !== 6) return jsonErr("Missing/invalid code", 400);

    if (purpose === "owner_signup") {
      if (!full_name) return jsonErr("Missing full_name", 400);
      if (!password || password.length < 8) return jsonErr("Password must be at least 8 characters", 400);
      if (!company_name) return jsonErr("Missing company_name", 400);
      if (!company_size) return jsonErr("Missing company_size", 400);
    }

    // ---- hash provided code ----
    const enc = new TextEncoder();
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(code + env.CODE_SALT));
    const code_hash = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // ---- fetch latest valid code row from signup_codes ----
    // NOTE: your table should be public.signup_codes with columns:
    // email (text), code_hash (text), purpose (text), company_code (text nullable), expires_at (timestamptz)
    const nowIso = new Date().toISOString();
    const q = new URL(`${env.SUPABASE_URL}/rest/v1/signup_codes`);
    q.searchParams.set("select", "id,email,code_hash,purpose,expires_at,company_code,created_at");
    q.searchParams.set("email", `eq.${email}`);
    q.searchParams.set("purpose", `eq.${purpose}`);
    q.searchParams.set("expires_at", `gt.${nowIso}`);
    q.searchParams.set("order", "created_at.desc");
    q.searchParams.set("limit", "1");

    const codeRes = await fetch(q.toString(), {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });

    if (!codeRes.ok) {
      const t = await codeRes.text();
      return jsonErr(`Supabase lookup failed: ${t}`, 500);
    }

    const rows = await codeRes.json();
    const row = rows && rows[0];
    if (!row) return jsonErr("Code not found or expired. Please request a new one.", 400);
    if (String(row.code_hash) !== code_hash) return jsonErr("Incorrect code. Please try again.", 400);

    // ---- consume the code (delete row) so it can't be reused ----
    // (Even if later steps fail, they can request a new code)
    if (row.id) {
      const del = await fetch(`${env.SUPABASE_URL}/rest/v1/signup_codes?id=eq.${encodeURIComponent(row.id)}`, {
        method: "DELETE",
        headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        },
      });
      // If delete fails, still continue but log it in response if needed
      if (!del.ok) {
        const dt = await del.text();
        // Not fatal, but useful for debugging:
        // return jsonErr(`Code verified but failed to delete code row: ${dt}`, 500);
      }
    }

    // ---- owner signup: create auth user AFTER code verified ----
    if (purpose !== "owner_signup") {
      return jsonOk({ ok: true, message: "Code verified." });
    }

    // Create user via Supabase Admin API
    // https://supabase.com/docs/reference/javascript/auth-admin-createuser (but here we call REST)
    const createUserRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        user_metadata: {
          full_name,
          role: "owner",
        },
      }),
    });

    const createUserText = await createUserRes.text();
    let createdUser = null;
    try {
      createdUser = JSON.parse(createUserText);
    } catch {
      // leave as null
    }

    if (!createUserRes.ok) {
      // Common causes:
      // - "User already registered"
      // - Password policy issues
      // - Wrong service role key / wrong Supabase URL
      return jsonErr(`Create user failed: ${createUserText}`, 500);
    }

    const userId = createdUser?.id;
    if (!userId) return jsonErr(`Create user failed (no id): ${createUserText}`, 500);

    // ---- create a company id/code ----
    const companyCode = makeCompanyCode(company_name);

    // Your companies table MUST have:
    // id uuid primary key default gen_random_uuid()
    // owner_user_id uuid references auth.users(id)
    // company_name text
    // company_code text (unique)
    // company_size text
    // address text nullable
    const companyPayload = {
      owner_user_id: userId,
      company_name,
      company_code: companyCode,
      company_size,
      address: body.address ? String(body.address).trim() : null,
    };

    const compIns = await fetch(`${env.SUPABASE_URL}/rest/v1/companies`, {
      method: "POST",
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "content-type": "application/json",
        prefer: "return=representation",
      },
      body: JSON.stringify(companyPayload),
    });

    const compText = await compIns.text();
    let compRow = null;
    try { compRow = JSON.parse(compText)?.[0] || JSON.parse(compText); } catch {}

    if (!compIns.ok) {
      return jsonErr(`Create company failed: ${compText}`, 500);
    }

    // ---- optional: store module purchases for the company ----
    // If you have a purchases table, wire it here. For now we just return module_ids as owned.
    return jsonOk({
      ok: true,
      user: { id: userId, email },
      company: compRow || null,
      owned_module_ids: module_ids,
    });
  } catch (e) {
    return jsonErr(`Error: ${e?.message || e}`, 500);
  }
}

/* ---------- helpers ---------- */
function jsonOk(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "content-type": "application/json" },
  });
}
function jsonErr(message, status = 500) {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeCompanyCode(companyName) {
  const letters = companyName.replace(/[^a-zA-Z]/g, "").toUpperCase().slice(0, 3).padEnd(3, "X");
  const num = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
  return `${letters}${num}`;
}

