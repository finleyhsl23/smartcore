export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const purpose = String(body.purpose || "owner_signup");
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();

    const password = String(body.password || "");
    const company_name = String(body.company_name || "").trim();
    const company_size = body.company_size ? String(body.company_size) : null;
    const module_ids = Array.isArray(body.module_ids) ? body.module_ids.map(String) : [];

    if (!env.SUPABASE_URL) return jsonErr("Missing SUPABASE_URL env var");
    if (!env.SUPABASE_SERVICE_ROLE_KEY) return jsonErr("Missing SUPABASE_SERVICE_ROLE_KEY env var");
    if (!env.CODE_SALT) return jsonErr("Missing CODE_SALT env var");

    if (!email) return jsonErr("Missing email", 400);
    if (!code || code.length !== 6) return jsonErr("Invalid code", 400);

    if (purpose !== "owner_signup") {
      return jsonErr("Invalid purpose for this endpoint", 400);
    }

    if (!password || password.length < 8) return jsonErr("Password must be at least 8 characters", 400);
    if (!company_name) return jsonErr("Missing company_name", 400);

    // 1) Verify code against stored hash
    const code_hash = await sha256Hex(code + env.CODE_SALT);

    const codesRes = await fetch(`${env.SUPABASE_URL}/rest/v1/signup_codes?select=*&email=eq.${encodeURIComponent(email)}&purpose=eq.owner_signup&order=created_at.desc&limit=1`, {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });

    if (!codesRes.ok) {
      const t = await codesRes.text();
      return jsonErr(`Failed reading signup_codes: ${t}`);
    }

    const codes = await codesRes.json();
    const rec = codes?.[0];
    if (!rec) return jsonErr("No code request found for this email. Please send a new code.", 400);

    const now = Date.now();
    const exp = rec.expires_at ? Date.parse(rec.expires_at) : 0;
    if (!exp || exp < now) return jsonErr("Code expired. Please request a new one.", 400);

    if (String(rec.code_hash) !== String(code_hash)) return jsonErr("Incorrect code. Please try again.", 400);

    // 2) Create user (auth admin API)
    // First check if user already exists
    const listRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`, {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });

    if (listRes.ok) {
      const list = await listRes.json().catch(() => null);
      const existing = Array.isArray(list?.users) ? list.users.find(u => String(u.email || "").toLowerCase() === email) : null;
      if (existing?.id) {
        return jsonOk({ ok: true, status: "EMAIL_EXISTS" });
      }
    }

    const createRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true
      })
    });

    if (!createRes.ok) {
      const t = await createRes.text();
      return jsonErr(`Create user failed: ${t}`);
    }

    const created = await createRes.json().catch(() => null);
    const user_id = created?.id;
    if (!user_id) return jsonErr("Create user failed (no id)");

    // 3) Create company (id should default gen_random_uuid())
    // Generate company_code: first 3 letters of company + 6 digits
    const prefix = company_name.replace(/[^A-Za-z]/g, "").slice(0,3).toUpperCase().padEnd(3, "X");
    let company_code = `${prefix}${Math.floor(100000 + Math.random()*900000)}`;

    // Ensure unique company_code (retry)
    for (let i=0;i<10;i++){
      const check = await fetch(`${env.SUPABASE_URL}/rest/v1/companies?select=id&company_code=eq.${company_code}&limit=1`, {
        headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        }
      });
      const rows = check.ok ? await check.json().catch(()=>[]) : [];
      if (!rows?.length) break;
      company_code = `${prefix}${Math.floor(100000 + Math.random()*900000)}`;
    }

    const compIns = await fetch(`${env.SUPABASE_URL}/rest/v1/companies`, {
      method: "POST",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=representation"
      },
      body: JSON.stringify([{
        company_name,
        owner_user_id: user_id,
        company_code
      }])
    });

    if (!compIns.ok) {
      const t = await compIns.text();
      return jsonErr(`Create company failed: ${t}`);
    }

    const compRow = (await compIns.json().catch(()=>null))?.[0];
    const company_id = compRow?.id;
    if (!company_id) return jsonErr("Company created but no id returned.");

    // 4) Create profile (owner)
    const profIns = await fetch(`${env.SUPABASE_URL}/rest/v1/profiles`, {
      method: "POST",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=minimal"
      },
      body: JSON.stringify([{
        user_id,
        company_id,
        full_name: null,
        job_title: null,
        job_category: null,
        is_admin: true
      }])
    });
    // ignore if already exists
    if (!profIns.ok) {
      // don't hard-fail onboarding for profile insert conflicts
    }

    // 5) Subscriptions (testing mode)
    const subIns = await fetch(`${env.SUPABASE_URL}/rest/v1/subscriptions`, {
      method: "POST",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=minimal"
      },
      body: JSON.stringify([{
        company_id,
        company_size,
        module_ids
      }])
    });
    if (!subIns.ok) {
      // allow continue if subs already exists etc
    }

    // 6) Consume code (delete it)
    await fetch(`${env.SUPABASE_URL}/rest/v1/signup_codes?email=eq.${encodeURIComponent(email)}&purpose=eq.owner_signup`, {
      method: "DELETE",
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });

    return jsonOk({ ok: true, user_id, company_id, company_code });

  } catch (e) {
    return jsonErr(`Error: ${e?.message || e}`);
  }
}

function jsonOk(obj, status=200){
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type":"application/json" }
  });
}
function jsonErr(msg, status=500){
  return new Response(JSON.stringify({ ok:false, error: msg }), {
    status,
    headers: { "content-type":"application/json" }
  });
}

async function sha256Hex(str){
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}
