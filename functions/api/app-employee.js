export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const company_id = String(body.company_id || "").trim();
    const company_code = String(body.company_code || "").trim().toUpperCase();
    const full_name = String(body.full_name || "").trim();
    const job_title = String(body.job_title || "").trim();
    const job_category = String(body.job_category || "").trim();
    const is_admin = !!body.is_admin;

    if (!env.SUPABASE_URL) return jsonErr("Missing SUPABASE_URL env var");
    if (!env.SUPABASE_SERVICE_ROLE_KEY) return jsonErr("Missing SUPABASE_SERVICE_ROLE_KEY env var");

    if (!company_id) return jsonErr("Missing company_id", 400);
    if (!company_code || company_code.length < 3) return jsonErr("Missing company_code", 400);
    if (!full_name) return jsonErr("Missing full_name", 400);

    const prefix = company_code.slice(0,3).toUpperCase();

    // Generate unique employee_code: PREFIX + 9 digits
    let employee_code = `${prefix}${Math.floor(Math.random()*1e9).toString().padStart(9,"0")}`;

    for (let i=0;i<12;i++){
      const check = await fetch(`${env.SUPABASE_URL}/rest/v1/employees?select=id&employee_code=eq.${employee_code}&limit=1`, {
        headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        }
      });
      const rows = check.ok ? await check.json().catch(()=>[]) : [];
      if (!rows?.length) break;
      employee_code = `${prefix}${Math.floor(Math.random()*1e9).toString().padStart(9,"0")}`;
    }

    const ins = await fetch(`${env.SUPABASE_URL}/rest/v1/employees`, {
      method: "POST",
      headers: {
        "content-type":"application/json",
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        prefer: "return=representation"
      },
      body: JSON.stringify([{
        company_id,
        full_name,
        job_title,
        job_category,
        employee_code,
        is_admin
      }])
    });

    if (!ins.ok){
      const t = await ins.text();
      return jsonErr(`Add employee failed: ${t}`);
    }

    const row = (await ins.json().catch(()=>null))?.[0];
    return jsonOk({ ok:true, employee: row });

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
