export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const code = String(body.code || "").trim();
    const company_code = String(body.company_code || "").trim().toUpperCase();
    const full_name = String(body.full_name || "").trim();

    if (!env.SUPABASE_URL) return jsonErr("Missing SUPABASE_URL env var");
    if (!env.SUPABASE_SERVICE_ROLE_KEY) return jsonErr("Missing SUPABASE_SERVICE_ROLE_KEY env var");
    if (!env.CODE_SALT) return jsonErr("Missing CODE_SALT env var");

    if (!email) return jsonErr("Missing email", 400);
    if (!password || password.length < 8) return jsonErr("Password must be at least 8 characters", 400);
    if (!company_code) return jsonErr("Missing company_code", 400);
    if (!full_name) return jsonErr("Missing full_name", 400);
    if (!code || code.length !== 6) return jsonErr("Invalid code", 400);

    // verify code
    const code_hash = await sha256Hex(code + env.CODE_SALT);
    const codesRes = await fetch(`${env.SUPABASE_URL}/rest/v1/signup_codes?select=*&email=eq.${encodeURIComponent(email)}&purpose=eq.employee_signup&company_code=eq.${encodeURIComponent(company_code)}&order=created_at.desc&limit=1`, {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });

    if (!codesRes.ok){
      const t = await codesRes.text();
      return jsonErr(`Failed reading signup_codes: ${t}`);
    }

    const codes = await codesRes.json();
    const rec = codes?.[0];
    if (!rec) return jsonErr("No code request found. Please send a new code.", 400);

    const exp = rec.expires_at ? Date.parse(rec.expires_at) : 0;
    if (!exp || exp < Date.now()) return jsonErr("Code expired. Please request a new one.", 400);
    if (String(rec.code_hash) !== String(code_hash)) return jsonErr("Incorrect code. Please try again.", 400);

    // Find company
    const compRes = await fetch(`${env.SUPABASE_URL}/rest/v1/companies?select=*&company_code=eq.${encodeURIComponent(company_code)}&limit=1`, {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });
    if (!compRes.ok){
      const t = await compRes.text();
      return jsonErr(`Company lookup failed: ${t}`);
    }
    const comp = (await compRes.json().catch(()=>[]))?.[0];
    if (!comp) return jsonErr("Company ID not found. Please check the code and try again.", 400);

    // Find employee by name (exact match after trim, case-insensitive)
    const empRes = await fetch(`${env.SUPABASE_URL}/rest/v1/employees?select=*&company_id=eq.${comp.id}&limit=200`, {
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });
    if (!empRes.ok){
      const t = await empRes.text();
      return jsonErr(`Employee lookup failed: ${t}`);
    }
    const emps = await empRes.json().catch(()=>[]);
    const match = emps.find(e => String(e.full_name || "").trim().toLowerCase() === full_name.trim().toLowerCase());

    if (!match){
      return jsonErr(
        "We couldn’t find your details under this company yet. Please ask your company admin to add you as an employee, then try again.",
        400
      );
    }

    // Create auth user
    const createRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true
      })
    });

    if (!createRes.ok){
      const t = await createRes.text();
      return jsonErr(`Create user failed: ${t}`);
    }
    const created = await createRes.json().catch(()=>null);
    const user_id = created?.id;
    if (!user_id) return jsonErr("Create user failed (no id)");

    // Link employee row + create profile
    await fetch(`${env.SUPABASE_URL}/rest/v1/employees?id=eq.${match.id}`, {
      method: "PATCH",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=minimal"
      },
      body: JSON.stringify({ user_id })
    });

    await fetch(`${env.SUPABASE_URL}/rest/v1/profiles`, {
      method: "POST",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=minimal"
      },
      body: JSON.stringify([{
        user_id,
        company_id: comp.id,
        full_name: match.full_name,
        job_title: match.job_title,
        job_category: match.job_category,
        is_admin: !!match.is_admin
      }])
    });

    // consume code
    await fetch(`${env.SUPABASE_URL}/rest/v1/signup_codes?email=eq.${encodeURIComponent(email)}&purpose=eq.employee_signup&company_code=eq.${encodeURIComponent(company_code)}`, {
      method: "DELETE",
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      }
    });

    return jsonOk({ ok:true, user_id, company_id: comp.id });

  } catch (e) {
    return jsonErr(`Error: ${e?.message || e}`);
  }
}

function jsonOk(obj, status=200){
  return new Response(JSON.stringify(obj), { status, headers:{ "content-type":"application/json" }});
}
function jsonErr(msg, status=500){
  return new Response(JSON.stringify({ ok:false, error: msg }), { status, headers:{ "content-type":"application/json" }});
}
async function sha256Hex(str){
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}
