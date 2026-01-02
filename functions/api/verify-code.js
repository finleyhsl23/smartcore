// /functions/api/verify-code.js
export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const purpose = String(body.purpose || "owner_signup");
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();

    if (!email) return json({ ok: false, error: "Missing email" }, 400);
    if (!code || code.length !== 6) return json({ ok: false, error: "Missing 6-digit code" }, 400);

    if (!env.SUPABASE_URL) return json({ ok: false, error: "Missing SUPABASE_URL env var" }, 500);
    if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ ok: false, error: "Missing SUPABASE_SERVICE_ROLE_KEY env var" }, 500);
    if (!env.CODE_SALT) return json({ ok: false, error: "Missing CODE_SALT env var" }, 500);

    const sbUrl = env.SUPABASE_URL;
    const svc = env.SUPABASE_SERVICE_ROLE_KEY;

    // ---- hash the code (must match send-code.js) ----
    const code_hash = await sha256hex(code + env.CODE_SALT);

    // ---- fetch latest code row for email+purpose ----
    const q = new URL(`${sbUrl}/rest/v1/signup_codes`);
    q.searchParams.set("select", "id,email,code_hash,purpose,company_code,full_name,expires_at,used_at,created_at");
    q.searchParams.set("email", `eq.${email}`);
    q.searchParams.set("purpose", `eq.${purpose}`);
    q.searchParams.set("order", "created_at.desc");
    q.searchParams.set("limit", "1");

    const r = await fetch(q.toString(), {
      headers: {
        apikey: svc,
        authorization: `Bearer ${svc}`,
      },
    });

    if (!r.ok) {
      const t = await r.text();
      return json({ ok: false, error: `Supabase read failed: ${t}` }, 500);
    }

    const rows = await r.json().catch(() => []);
    const row = rows?.[0];

    if (!row) return json({ ok: false, error: "Code not found. Please request a new code." }, 400);
    if (row.used_at) return json({ ok: false, error: "That code has already been used. Please request a new one." }, 400);

    const exp = new Date(row.expires_at).getTime();
    if (!Number.isFinite(exp) || Date.now() > exp) {
      return json({ ok: false, error: "That code has expired. Please request a new code." }, 400);
    }

    if (String(row.code_hash) !== code_hash) {
      return json({ ok: false, error: "Incorrect code. Please try again." }, 400);
    }

    // ---- validate payload depending on purpose ----
    const password = String(body.password || "");
    if (!password || password.length < 8) {
      return json({ ok: false, error: "Password must be at least 8 characters" }, 400);
    }

    // OWNER SIGNUP REQUIRED
    const company_name = String(body.company_name || "").trim();
    const company_size = String(body.company_size || body.company_size_id || "").trim(); // allow either
    const max_employees = body.max_employees ?? null;

    // EMPLOYEE SIGNUP REQUIRED
    const company_code_from_body = body.company_code ? String(body.company_code).trim().toUpperCase() : null;
    const full_name_from_body = String(body.full_name || "").trim();

    if (purpose === "owner_signup") {
      if (!company_name) return json({ ok: false, error: "Missing company_name" }, 400);
      if (!company_size) return json({ ok: false, error: "Missing company_size" }, 400);
      if (!full_name_from_body) return json({ ok: false, error: "Missing full_name" }, 400);
    }

    if (purpose === "employee_signup") {
      const cc = company_code_from_body || (row.company_code ? String(row.company_code).trim().toUpperCase() : null);
      const fn = full_name_from_body || (row.full_name ? String(row.full_name).trim() : null);

      if (!cc) return json({ ok: false, error: "Missing company_code" }, 400);
      if (!fn) return json({ ok: false, error: "Missing full_name" }, 400);
    }

    // ---- mark code as used FIRST to prevent race reuse ----
    // (if later steps fail, user can request a new code)
    const usedPatch = await fetch(`${sbUrl}/rest/v1/signup_codes?id=eq.${encodeURIComponent(row.id)}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        apikey: svc,
        authorization: `Bearer ${svc}`,
        prefer: "return=minimal",
      },
      body: JSON.stringify({ used_at: new Date().toISOString() }),
    });

    if (!usedPatch.ok) {
      const t = await usedPatch.text();
      return json({ ok: false, error: `Failed to mark code used: ${t}` }, 500);
    }

    // ---- create auth user (Admin API) ----
    const createUserRes = await fetch(`${sbUrl}/auth/v1/admin/users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        apikey: svc,
        authorization: `Bearer ${svc}`,
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: full_name_from_body || row.full_name || "" },
      }),
    });

    if (!createUserRes.ok) {
      const t = await createUserRes.text();

      // Common: user already exists
      if (String(t).toLowerCase().includes("already") || String(t).toLowerCase().includes("exists")) {
        return json({ ok: false, error: "This email is already registered. Please log in instead." }, 409);
      }

      return json({ ok: false, error: `Create user failed: ${t}` }, 500);
    }

    const created = await createUserRes.json().catch(() => ({}));
    const user_id = created?.id;
    if (!user_id) return json({ ok: false, error: "Create user failed (no id)" }, 500);

    // ---- OWNER SIGNUP: create company + profile ----
    if (purpose === "owner_signup") {
      const new_company_code = await makeCompanyCode(company_name);

      // Create company (match your table columns)
      const insCompany = await fetch(`${sbUrl}/rest/v1/companies`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          apikey: svc,
          authorization: `Bearer ${svc}`,
          prefer: "return=representation",
        },
        body: JSON.stringify([{
          company_name,
          owner_user_id: user_id,
          company_code: new_company_code,
          company_size,           // your companies table shows company_size text
          max_employees: max_employees ?? null, // only if column exists
        }]),
      });

      if (!insCompany.ok) {
        const t = await insCompany.text();
        return json({ ok: false, error: `Create company failed: ${t}` }, 500);
      }

      const cRows = await insCompany.json().catch(() => []);
      const company = cRows?.[0];
      const company_id = company?.id;
      if (!company_id) return json({ ok: false, error: "Create company failed (no company id returned)" }, 500);

      // Create profile (your profiles table uses user_id, NOT id)
      const insProfile = await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          apikey: svc,
          authorization: `Bearer ${svc}`,
          prefer: "return=minimal",
        },
        body: JSON.stringify([{
          user_id,
          email,
          company_id,
          company_name,
          full_name: full_name_from_body,
          role: "owner",
          is_admin: true, // IMPORTANT: should be boolean in DB
        }]),
      });

      if (!insProfile.ok) {
        const t = await insProfile.text();
        return json({ ok: false, error: `Create profile failed: ${t}` }, 500);
      }

      return json({
        ok: true,
        created: true,
        purpose,
        user_id,
        company_id,
        company_code: company.company_code,
      });
    }

    // ---- EMPLOYEE SIGNUP: attach to existing company ----
    if (purpose === "employee_signup") {
      const company_code = company_code_from_body || String(row.company_code || "").trim().toUpperCase();
      const full_name = full_name_from_body || String(row.full_name || "").trim();

      // Find company by code
      const coRes = await fetch(
        `${sbUrl}/rest/v1/companies?select=id,company_name,company_code&company_code=eq.${encodeURIComponent(company_code)}&limit=1`,
        {
          headers: {
            apikey: svc,
            authorization: `Bearer ${svc}`,
          },
        }
      );

      const coArr = await coRes.json().catch(() => []);
      const company = coArr?.[0];
      if (!company?.id) {
        return json({ ok: false, error: "Company not found for that company code." }, 400);
      }

      // Create profile for employee
      const insProfile = await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          apikey: svc,
          authorization: `Bearer ${svc}`,
          prefer: "return=minimal",
        },
        body: JSON.stringify([{
          user_id,
          email,
          company_id: company.id,
          company_name: company.company_name,
          full_name,
          role: "employee",
          is_admin: false,
        }]),
      });

      if (!insProfile.ok) {
        const t = await insProfile.text();
        return json({ ok: false, error: `Create profile failed: ${t}` }, 500);
      }

      return json({
        ok: true,
        created: true,
        purpose,
        user_id,
        company_id: company.id,
        company_code: company.company_code,
      });
    }

    return json({ ok: false, error: "Unsupported purpose" }, 400);

  } catch (e) {
    return json({ ok: false, error: `Error: ${e?.message || e}` }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function sha256hex(input) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function makeCompanyCode(companyName) {
  const prefix = (companyName.replace(/[^a-z0-9]/gi, "").toUpperCase().slice(0, 3) || "COM");
  const n = String(Math.floor(100000 + Math.random() * 900000));
  return `${prefix}${n}`;
}
