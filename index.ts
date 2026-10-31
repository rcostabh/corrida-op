// Função do servidor: convida pessoas e envia link de nova senha.
// Só o gestor pode chamar. Usa a chave secreta que o próprio Supabase injeta (nunca vai para o navegador).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const json = (b: unknown, s = 200) =>
    new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

  try {
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
      auth: { persistSession: false },
    });

    // 1. Quem está chamando? Precisa ser gestor ativo.
    const jwt = (req.headers.get("Authorization") || "").replace(/^Bearer /i, "");
    const { data: u, error: ue } = await admin.auth.getUser(jwt);
    if (ue || !u?.user) return json({ erro: "Sessão inválida. Entre de novo." }, 401);
    const { data: eu } = await admin.from("usuarios").select("id,papel,ativo").eq("auth_id", u.user.id).maybeSingle();
    if (!eu || !["gestor", "assistente"].includes(eu.papel) || !eu.ativo) return json({ erro: "Apenas o gestor ou o assistente pode fazer isso." }, 403);
    const master = eu.papel === "gestor";
    // Gestor e assistente só podem ser mexidos pelo gestor master.
    const protegido = async (id: unknown) => {
      const { data: t } = await admin.from("usuarios").select("papel").eq("id", id).maybeSingle();
      return !!t && ["gestor", "assistente"].includes(t.papel) && !master;
    };

    const b = await req.json();
    const redirectTo = String(b.redirectTo || "");

    // 2. Enviar link de nova senha para uma pessoa já cadastrada.
    if (b.acao === "redefinir") {
      if (await protegido(b.pessoa_id)) return json({ erro: "Só o gestor master mexe em gestores e assistentes." }, 403);
      const { data: p } = await admin.from("usuarios").select("email").eq("id", b.pessoa_id).maybeSingle();
      if (!p?.email) return json({ erro: "Pessoa sem e-mail cadastrado." }, 400);
      const { error } = await admin.auth.resetPasswordForEmail(p.email, { redirectTo });
      if (error) return json({ erro: error.message }, 400);
      return json({ ok: true });
    }

    // 2b. Trocar o e-mail de uma pessoa e mandar link para ela criar a senha no novo endereço.
    if (b.acao === "trocar_email") {
      const novo = String(b.email || "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(novo)) return json({ erro: "E-mail inválido." }, 400);
      if (await protegido(b.pessoa_id)) return json({ erro: "Só o gestor master mexe em gestores e assistentes." }, 403);
      const { data: p } = await admin.from("usuarios").select("id,auth_id").eq("id", b.pessoa_id).maybeSingle();
      if (!p?.auth_id) return json({ erro: "Pessoa não encontrada." }, 404);
      const { data: igual } = await admin.from("usuarios").select("id").eq("email", novo).neq("id", p.id).maybeSingle();
      if (igual) return json({ erro: "Já existe uma pessoa com este e-mail." }, 400);
      const { error: ae } = await admin.auth.admin.updateUserById(p.auth_id, { email: novo, email_confirm: true });
      if (ae) return json({ erro: ae.message }, 400);
      const { error: de } = await admin.from("usuarios").update({ email: novo }).eq("id", p.id);
      if (de) return json({ erro: de.message }, 400);
      const { error: re } = await admin.auth.resetPasswordForEmail(novo, { redirectTo });
      if (re) return json({ ok: true, aviso: "E-mail trocado, mas o link de senha não foi enviado: " + re.message });
      return json({ ok: true });
    }

    // 2c. Dar acesso a quem foi cadastrado sem convite: manda o convite para o e-mail já salvo.
    if (b.acao === "convidar_existente") {
      if (await protegido(b.pessoa_id)) return json({ erro: "Só o gestor master mexe em gestores e assistentes." }, 403);
      const { data: p } = await admin.from("usuarios").select("id,auth_id,email,nome").eq("id", b.pessoa_id).maybeSingle();
      if (!p) return json({ erro: "Pessoa não encontrada." }, 404);
      if (p.auth_id) return json({ erro: "Esta pessoa já tem acesso." }, 400);
      if (!p.email) return json({ erro: "Cadastre o e-mail da pessoa antes de convidar." }, 400);
      const { data: inv, error: ie } = await admin.auth.admin.inviteUserByEmail(p.email, { redirectTo, data: { nome: p.nome } });
      if (ie || !inv?.user) return json({ erro: ie?.message || "Não foi possível enviar o convite." }, 400);
      const { error: ue2 } = await admin.from("usuarios").update({ auth_id: inv.user.id }).eq("id", p.id);
      if (ue2) { await admin.auth.admin.deleteUser(inv.user.id); return json({ erro: ue2.message }, 400); }
      return json({ ok: true });
    }

    // 3. Convidar.
    if (b.acao !== "convidar") return json({ erro: "Ação desconhecida." }, 400);
    const nome = String(b.nome || "").trim();
    const email = String(b.email || "").trim().toLowerCase();
    const telefone = String(b.telefone || "").replace(/\D/g, "");
    const papel = b.papel;
    const cargo = papel === "promotor" ? b.cargo : null;
    if (!["gerente", "promotor", "assistente"].includes(papel)) return json({ erro: "Escolha gerente, promotor ou assistente." }, 400);
    if (papel === "assistente" && !master) return json({ erro: "Só o gestor master cadastra assistentes." }, 403);
    if (!nome) return json({ erro: "Informe o nome." }, 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ erro: "E-mail inválido." }, 400);
    if (!/^[0-9]{10,11}$/.test(telefone)) return json({ erro: "Telefone com DDD, 10 ou 11 números." }, 400);
    if (papel === "promotor" && !["Promotor", "Tele BH", "Tele interno", "Divulgador", "Luminoso"].includes(cargo)) return json({ erro: "Escolha o cargo." }, 400);
    let cl: { id: number } | null = null;
    if (papel !== "assistente") {
      const { data } = await admin.from("clinicas").select("id").eq("id", b.clinica_id).maybeSingle();
      cl = data;
      if (!cl) return json({ erro: "Escolha a clínica." }, 400);
    }
    const { data: ja } = await admin.from("usuarios").select("id").eq("email", email).maybeSingle();
    if (ja) return json({ erro: "Já existe uma pessoa com este e-mail." }, 400);

    // login interno único, derivado do e-mail
    let base = email.split("@")[0].replace(/[^a-z0-9._-]/g, ".").slice(0, 24);
    if (base.length < 3) base = (base + "usr").slice(0, 24);
    const { data: usados } = await admin.from("usuarios").select("login").like("login", base + "%");
    const set = new Set((usados || []).map((x: { login: string }) => x.login));
    let login = base, n = 2;
    while (set.has(login)) login = base + n++;

    const { data: inv, error: ie } = await admin.auth.admin.inviteUserByEmail(email, { redirectTo, data: { nome } });
    if (ie || !inv?.user) return json({ erro: ie?.message || "Não foi possível enviar o convite." }, 400);

    const { data: novo, error: ne } = await admin.from("usuarios")
      .insert({ auth_id: inv.user.id, papel, nome, telefone, email, cargo, login })
      .select("id").single();
    if (ne) { await admin.auth.admin.deleteUser(inv.user.id); return json({ erro: ne.message }, 400); }

    if (!cl) return json({ ok: true, id: novo.id });
    const { error: ve } = await admin.from("vinculos_clinica").insert({ usuario_id: novo.id, clinica_id: cl.id });
    if (ve) {
      await admin.from("usuarios").delete().eq("id", novo.id);
      await admin.auth.admin.deleteUser(inv.user.id);
      return json({ erro: ve.message }, 400);
    }
    return json({ ok: true, id: novo.id });
  } catch (e) {
    return json({ erro: String((e as Error).message || e) }, 500);
  }
});
