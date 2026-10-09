# -*- coding: utf-8 -*-
# Funcion serverless de Vercel: GET /api/scan?url=...&max=..&write=0|1&key=..
# Rastrea un sitio, analiza HTML/JS, prueba RLS de Supabase y arma el SQL.
# Solo librerias estandar. Pensado para auditar sitios propios.
import re, ssl, json, socket, base64, time
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from http.server import BaseHTTPRequestHandler

TIMEOUT = 7           # por pedido
BUDGET = 48           # presupuesto total de segundos (Vercel corta ~60s)
UA = "ZH-Auditor/4.0 (auditoria propia)"
CTX = ssl.create_default_context()

ARCHIVOS = [".env", ".env.local", ".git/config", ".git/HEAD", "config.json",
    "admins_config.json", "thor_config.json", "secrets.json", "credentials.json",
    "serviceAccount.json", "vercel.json", "package.json", "backup.sql", "dump.sql",
    "database.sql", "db.sqlite", "data.db", "config.php", ".htpasswd", "id_rsa"]
SECRETOS = [
    ("Token de bot de Discord", "CRITICO", re.compile(r"[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}")),
    ("Webhook de Discord", "CRITICO", re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")),
    ("Token de bot de Telegram", "CRITICO", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("Clave privada (PEM)", "CRITICO", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Stripe secret key (LIVE)", "CRITICO", re.compile(r"sk_live_[0-9A-Za-z]{20,}")),
    ("AWS Access Key", "CRITICO", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key (AIza)", "ALTO", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Mailgun / SendGrid key", "ALTO", re.compile(r"SG\.[\w-]{20,}\.[\w-]{20,}")),
]
VAR_SECRET = re.compile(r"""(?ix)\b([A-Za-z_$][\w$]*(?:key|token|secret|pass|clave|pin|pwd|apikey|webhook)[\w$]*)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]""")
HEADERS_SEG = ["content-security-policy", "x-frame-options", "strict-transport-security",
               "x-content-type-options", "referrer-policy", "permissions-policy"]

def mask(v):
    v = str(v)
    return v[:4] + "..." + ("(" + str(len(v)) + " chars)" if len(v) > 10 else "")

def rol_jwt(tok):
    try:
        p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return None

def pedir(url, metodo="GET", rango=None, headers=None, data=None):
    h = {"User-Agent": UA}
    if rango: h["Range"] = rango
    if headers: h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode(); h.setdefault("Content-Type", "application/json")
    req = Request(url, headers=h, method=metodo, data=body)
    try:
        r = urlopen(req, timeout=TIMEOUT, context=CTX)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(900_000).decode("utf-8", "replace")
    except HTTPError as e:
        try: cuerpo = e.read(16000).decode("utf-8", "replace")
        except Exception: cuerpo = ""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, cuerpo
    except (URLError, socket.timeout, Exception) as e:
        return None, {}, "ERR:" + str(e)

def escanear(texto, origen, F, sb):
    def add(sev, t):
        if not any(x["txt"] == t for x in F): F.append({"sev": sev, "txt": t})
    for nombre, sev, rx in SECRETOS:
        m = rx.search(texto)
        if m: add(sev, "Secreto en " + origen + ": " + nombre + " = " + mask(m.group(0)))
    vistos = set()
    for m in VAR_SECRET.finditer(texto):
        if m.group(1) in vistos: continue
        vistos.add(m.group(1))
        add("MEDIO", "Variable sensible en " + origen + ": " + m.group(1) + " = " + mask(m.group(2)))
    if re.search(r"localStorage\.setItem\(['\"]\w*sesion['\"]\s*,\s*btoa", texto) or re.search(r"btoa\([^)]*\+\s*['\"]:['\"]", texto):
        add("ALTO", "Sesion con btoa en " + origen + " (falsificable, sin validacion en servidor)")
    if re.search(r"(?:is|es)[_]?[Aa]dmin\s*[=:]|_esAdmin|vh_admin_pass|ADMIN_PASS\s*=", texto):
        add("ALTO", "Modo admin decidido en el cliente en " + origen)
    if re.search(r"\beval\s*\(|new Function\s*\(", texto):
        add("ALTO", str(len(re.findall(r"\beval\s*\(|new Function\s*\(", texto))) + " uso(s) de eval/new Function en " + origen)
    inner = len(re.findall(r"\.innerHTML\s*\+?=", texto))
    if inner > 20: add("MEDIO", str(inner) + " asignaciones innerHTML en " + origen)
    mu = re.search(r"https://([a-z0-9]{15,30})\.supabase\.co", texto)
    if mu: sb["url"] = "https://" + mu.group(1) + ".supabase.co"
    for m in re.finditer(r"eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}", texto):
        p = rol_jwt(m.group(0))
        if p and p.get("role") == "service_role":
            add("CRITICO", "Clave service_role de Supabase EXPUESTA en " + origen)
        elif p and p.get("role") in ("anon", "authenticated") and not sb.get("key"):
            sb["key"] = m.group(0)
    m = re.search(r"sb_publishable_[A-Za-z0-9_\-]+", texto)
    if m and not sb.get("key"): sb["key"] = m.group(0)
    for t in re.findall(r"\.from\(\s*['\"`]([A-Za-z0-9_]+)", texto): sb["tablas"].add(t)
    for t in re.findall(r"rest/v1/([A-Za-z0-9_]+)", texto):
        if t != "rpc": sb["tablas"].add(t)

def probar_rls(sb, test_write, F, t0):
    base = sb["url"]; key = sb.get("key"); res = []
    if not (base and key and sb["tablas"]): return res
    H = {"apikey": key, "Authorization": "Bearer " + key}
    rest = base.rstrip("/") + "/rest/v1/"
    for t in sorted(sb["tablas"]):
        if time.monotonic() - t0 > BUDGET: break
        st, hd, body = pedir(rest + t + "?select=*&limit=1", headers=H)
        if st == 200:
            lect = "ABIERTA"; F.append({"sev": "CRITICO", "txt": "Tabla '" + t + "': lectura anonima ABIERTA"})
        elif st in (401, 403): lect = "protegida"
        elif st == 404: lect = "no existe"
        else: lect = "HTTP " + str(st)
        escr = "-"
        if test_write and st not in (None, 404):
            sw, hw, bw = pedir(rest + t, metodo="POST", headers=dict(H, **{"Prefer": "return=representation"}), data={})
            if sw == 201:
                escr = "ABIERTA (se inserto fila)"
                F.append({"sev": "CRITICO", "txt": "Tabla '" + t + "': escritura anonima ABIERTA"})
                try:
                    fila = json.loads(bw)
                    if isinstance(fila, list) and fila and "id" in fila[0]:
                        pedir(rest + t + "?id=eq." + str(fila[0]["id"]), metodo="DELETE", headers=dict(H, **{"Prefer": "return=minimal"}))
                        escr += " [borrada]"
                    else: escr += " [REVISAR A MANO]"
                except Exception: escr += " [REVISAR A MANO]"
            elif sw == 400 and ("23502" in bw or "null value" in bw):
                escr = "ABIERTA (RLS no bloquea)"; F.append({"sev": "CRITICO", "txt": "Tabla '" + t + "': INSERT anonimo ABIERTO"})
            elif sw in (401, 403): escr = "protegida"
            else: escr = "HTTP " + str(sw)
        res.append({"tabla": t, "lectura": lect, "escritura": escr})
    return res

def gen_sql(host, abiertas):
    if not abiertas: return ""
    lista = ",\n                        ".join("'" + t + "'" for t in sorted(abiertas))
    L = ["-- CIERRE DE POLITICAS RLS  -  " + host,
         "-- Probalo en una copia de la base primero.", "", "do $$", "declare p record;", "begin", "  for p in",
         "    select policyname, tablename from pg_policies",
         "    where schemaname='public' and tablename in (" + lista + ")",
         "  loop", "    execute format('drop policy %I on public.%I', p.policyname, p.tablename);",
         "  end loop;", "end $$;", "",
         "-- Lectura publica solo donde HAGA FALTA (borra las que no deban leerse sin login):"]
    for t in sorted(abiertas):
        L.append("create policy lectura_publica on public.%s for select using (true);" % t)
    L += ["", "-- La escritura queda cerrada: solo con service_role desde el servidor."]
    return "\n".join(L)

def auditar(url, maxp, test_write, key_override):
    t0 = time.monotonic()
    if not url.startswith("http"): url = "https://" + url
    base = "{0.scheme}://{0.netloc}/".format(urlparse(url))
    host = urlparse(base).netloc
    out = {"target": base, "headers": {}, "paginas": [], "findings": [], "supabase": None,
           "apis": [], "hosts": [], "archivos": [], "rls": [], "sql": "", "error": None, "stats": {}}
    F = out["findings"]; sb = {"url": None, "key": None, "tablas": set()}
    st, hd, _ = pedir(base)
    if st is None:
        out["error"] = "No se pudo conectar con " + base + ". Revisa la URL."
        return out
    for h in HEADERS_SEG:
        v = hd.get(h, "FALTA"); out["headers"][h] = v
        if v == "FALTA" and h in ("content-security-policy", "x-frame-options"):
            F.append({"sev": "MEDIO", "txt": "Falta cabecera " + h})
    pend = deque([url]); vistas = set(); js_pend = set(); apis = set(); hosts = set()
    while pend and len(vistas) < maxp and time.monotonic() - t0 < BUDGET:
        u = pend.popleft()
        if u in vistas: continue
        vistas.add(u)
        s, h, html = pedir(u)
        if s != 200 or not html or html.startswith("ERR:") or "html" not in h.get("content-type", "html"):
            continue
        has_lang = re.search(r"<html[^>]*\blang=['\"]([^'\"]+)", html, re.I)
        out["paginas"].append({"url": u, "bytes": len(html),
            "lang": has_lang.group(1) if has_lang else "FALTA",
            "description": bool(re.search(r"<meta[^>]+name=['\"]description['\"]", html, re.I)),
            "og": len(re.findall(r"<meta[^>]+property=['\"]og:", html, re.I)),
            "sw": bool(re.search(r"serviceWorker\.register", html))})
        escanear(html, u, F, sb)
        for m in re.finditer(r"src=['\"]([^'\"]+\.js[^'\"]*)", html):
            j = urljoin(u, m.group(1))
            if urlparse(j).netloc == host: js_pend.add(j)
        for a in re.findall(r"""['"`](/api/[A-Za-z0-9_\-/]+)""", html): apis.add(a)
        for hh in re.findall(r"https?://([a-z0-9.\-]+\.[a-z]{2,})", html, re.I): hosts.add(hh.lower())
        for m in re.finditer(r"""href=['"]([^'"#?]+)""", html):
            v = urljoin(u, m.group(1)); pu = urlparse(v)
            if pu.netloc == host and (pu.path.endswith((".html", "/")) or "." not in pu.path.split("/")[-1]):
                pend.append(v)
    for j in list(js_pend)[:15]:
        if time.monotonic() - t0 > BUDGET: break
        s, h, txt = pedir(j)
        if s == 200 and txt and not txt.startswith("ERR:"): escanear(txt, j, F, sb)
    for f in ARCHIVOS:
        if time.monotonic() - t0 > BUDGET: break
        s, h, _ = pedir(urljoin(base, f), rango="bytes=0-80")
        if s in (200, 206):
            out["archivos"].append(f); F.append({"sev": "CRITICO", "txt": "Archivo sensible publico: /" + f})
    if key_override: sb["key"] = key_override
    if sb["url"]:
        out["supabase"] = {"url": sb["url"], "key": mask(sb["key"]) if sb.get("key") else None, "tablas": sorted(sb["tablas"])}
        out["rls"] = probar_rls(sb, test_write, F, t0)
        abiertas = [r["tabla"] for r in out["rls"] if "ABIERTA" in r["lectura"] or "ABIERTA" in r["escritura"]]
        out["sql"] = gen_sql(host, abiertas)
    out["apis"] = sorted(apis); out["hosts"] = sorted(hosts)
    out["stats"] = {"paginas": len(vistas), "js": len(js_pend), "tablas": len(sb["tablas"]),
                    "segundos": round(time.monotonic() - t0, 1)}
    return out

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        url = (q.get("url") or [""])[0].strip()
        try: maxp = min(int((q.get("max") or ["8"])[0] or 8), 25)
        except Exception: maxp = 8
        write = (q.get("write") or ["0"])[0] == "1"
        key = (q.get("key") or [""])[0].strip() or None
        if not url:
            data = {"error": "Falta el parametro url."}
        else:
            try: data = auditar(url, maxp, write, key)
            except Exception as e: data = {"error": "Fallo la auditoria: " + str(e)}
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
