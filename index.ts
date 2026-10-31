// Função do servidor: convida pessoas, envia link de nova senha e dispara os avisos no celular.
// Convites e senhas: só gestor/assistente. Avisos: chamada do banco (segredo) ou teste da própria pessoa. Usa a chave secreta que o próprio Supabase injeta (nunca vai para o navegador).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};


// ===== webpush:inicio — avisos no celular (Web Push com VAPID), só com a criptografia nativa =====
const enc = new TextEncoder();
const b64u = (buf: ArrayBuffer | Uint8Array): string => {
  const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ""; for (const x of a) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (s: string): Uint8Array => {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  const bin = atob(s); const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
};
const cat = (...arrs: Uint8Array[]): Uint8Array => {
  const o = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let p = 0;
  for (const a of arrs) { o.set(a, p); p += a.length; }
  return o;
};
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
async function vapidAuth(endpoint: string, pub: string, priv: string, subject: string): Promise<string> {
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject })));
  const pb = unb64u(pub);
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: b64u(pb.slice(1, 33)), y: b64u(pb.slice(33, 65)), d: priv, ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + claims)));
  return "vapid t=" + head + "." + claims + "." + b64u(sig) + ", k=" + pub;
}
// Criptografia do conteúdo (RFC 8291, aes128gcm). "fixo" só existe para os testes.
async function cifrar(sub: { keys: { p256dh: string; auth: string } }, payload: Uint8Array, fixo?: { salt: Uint8Array; eph: CryptoKeyPair }): Promise<Uint8Array> {
  const uaPub = unb64u(sub.keys.p256dh), authSecret = unb64u(sub.keys.auth);
  const eph = fixo ? fixo.eph : await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(authSecret, ecdh, cat(enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = fixo ? fixo.salt : crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, cat(payload, new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([asPub.length]), asPub, ct);
}
// Devolve o status HTTP do serviço de push (201 = aceito; 404/410 = aparelho não existe mais).
async function enviarWebPush(sub: { endpoint: string; keys: { p256dh: string; auth: string } }, payload: unknown, pub: string, priv: string, subject: string): Promise<number> {
  const body = await cifrar(sub, enc.encode(JSON.stringify(payload)));
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: { Authorization: await vapidAuth(sub.endpoint, pub, priv, subject), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "high" },
    body,
  });
  return res.status;
}
// ===== webpush:fim =====

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const json = (b: unknown, s = 200) =>
    new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

  try {
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
      auth: { persistSession: false },
    });


    // Envia avisos para os aparelhos de uma pessoa. Aparelhos que não existem mais são apagados.
    const vapidPub = Deno.env.get("VAPID_PUBLIC_KEY") || "", vapidPriv = Deno.env.get("VAPID_PRIVATE_KEY") || "";
    const vapidSub = Deno.env.get("VAPID_SUBJECT") || "mailto:contato@example.com";
    const enviarPara = async (usuarioId: number, titulo: string, texto: string): Promise<number> => {
      if (!vapidPub || !vapidPriv) return 0;
      const { data: aps } = await admin.from("dispositivos_push").select("id,token").eq("usuario_id", usuarioId).eq("plataforma", "web");
      let ok = 0;
      for (const ap of aps || []) {
        try {
          const sub = JSON.parse(ap.token);
          const st = await enviarWebPush(sub, { titulo, texto }, vapidPub, vapidPriv, vapidSub);
          if (st >= 200 && st < 300) ok++;
          else if (st === 404 || st === 410) await admin.from("dispositivos_push").delete().eq("id", ap.id);
        } catch (_e) { /* aparelho com dado inválido: ignora */ }
      }
      return ok;
    };

    // 0. Chamada do próprio banco (Database Webhook): envia os avisos que ainda não saíram.
    const segredo = req.headers.get("x-push-secret");
    if (segredo) {
      const esperado = Deno.env.get("PUSH_SECRET");
      if (!esperado || segredo !== esperado) return json({ erro: "Não autorizado." }, 401);
      if (!vapidPub || !vapidPriv) return json({ erro: "Chaves VAPID não configuradas." }, 400); // não reserva nada enquanto não estiver pronto
      const { data: pend } = await admin.from("notificacoes").select("id").is("enviada_em", null).order("criada_em").limit(200);
      const ids = (pend || []).map((x: { id: number }) => x.id);
      if (!ids.length) return json({ ok: true, enviados: 0 });
      // "Reserva" os avisos antes de enviar, para que duas chamadas seguidas não mandem o mesmo aviso duas vezes.
      const { data: meus } = await admin.from("notificacoes").update({ enviada_em: new Date().toISOString() }).in("id", ids).is("enviada_em", null).select("usuario_id,titulo,texto");
      let n = 0;
      for (const m of meus || []) n += await enviarPara(m.usuario_id, m.titulo, m.texto);
      return json({ ok: true, avisos: (meus || []).length, enviados: n });
    }

    const b = await req.json().catch(() => ({}));

    // 1. Quem está chamando? Precisa estar logado.
    const jwt = (req.headers.get("Authorization") || "").replace(/^Bearer /i, "");
    const { data: u, error: ue } = await admin.auth.getUser(jwt);
    if (ue || !u?.user) return json({ erro: "Sessão inválida. Entre de novo." }, 401);
    const { data: eu } = await admin.from("usuarios").select("id,papel,ativo").eq("auth_id", u.user.id).maybeSingle();
    // Teste de aviso: qualquer pessoa ativa pode mandar um aviso de teste para os próprios aparelhos.
    if (b.acao === "teste_push") {
      if (!eu || !eu.ativo) return json({ erro: "Pessoa inativa." }, 403);
      if (!vapidPub || !vapidPriv) return json({ erro: "Os avisos ainda não foram configurados no servidor (chaves VAPID)." }, 400);
      const n = await enviarPara(eu.id, "Corrida OP", "Teste: os avisos estão funcionando neste aparelho.");
      return json({ ok: true, enviados: n });
    }
    // Daqui para a frente, só gestor ou assistente.
    if (!eu || !["gestor", "assistente"].includes(eu.papel) || !eu.ativo) return json({ erro: "Apenas o gestor ou o assistente pode fazer isso." }, 403);
    const master = eu.papel === "gestor";
    // Gestor e assistente só podem ser mexidos pelo gestor master.
    const protegido = async (id: unknown) => {
      const { data: t } = await admin.from("usuarios").select("papel").eq("id", id).maybeSingle();
      return !!t && ["gestor", "assistente"].includes(t.papel) && !master;
    };

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
    if (papel === "promotor" && !["Promotor", "Tele BH", "Tele interno", "Divulgador", "Luminoso", "Promotor de teste"].includes(cargo)) return json({ erro: "Escolha o cargo." }, 400);
    const hojeIso = new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 10); // horário de Brasília
    const inicio = String(b.inicio || hojeIso).slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(inicio) || isNaN(Date.parse(inicio)) || inicio > hojeIso) return json({ erro: "Data de início inválida (não pode ser futura)." }, 400);
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
    const { error: ve } = await admin.from("vinculos_clinica").insert({ usuario_id: novo.id, clinica_id: cl.id, inicio });
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
