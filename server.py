"""iPhone -> Windows ファイル転送サーバー（ワンタイムパスワード方式）

Windows 側で server.py をダブルクリックして起動し、ブラウザで http://localhost:8000 を開いてパスワードを発行する。
iPhone は同じネットワーク（Wi-Fi / iPhone のテザリング）から表示された URL を開き、
パスワードを入力して写真・PDF などのファイルを送る。
受け取ったファイルは received/ フォルダに保存される。

Python 3.8 以上・標準ライブラリのみで動作。
"""

import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.environ.get("PORT", "8000"))
PORT_RANGE = range(8000, 8011)   # 8000 が使用中なら 8010 まで順に試す
SAVE_DIR = Path(os.environ.get("SAVE_DIR", Path(__file__).resolve().parent / "received"))
CODE_TTL = 10 * 60          # パスワードの有効期限（秒）
TOKEN_TTL = 30 * 60         # パスワード使用後、送信できる時間（秒）
MAX_ATTEMPTS = 5            # 間違えられる回数。超えるとパスワードは無効
MAX_FILE_SIZE = 500 * 1024 * 1024
INLINE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "application/pdf"}

lock = threading.Lock()
state = {
    "code": None,
    "code_expires": 0.0,
    "attempts": 0,
    "token": None,
    "token_expires": 0.0,
    "files": [],            # [{"name": str, "path": Path, "size": int, "time": float}]
}


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def all_ips():
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
    except OSError:
        ips = set()
    ips.add(lan_ip())
    return sorted(ip for ip in ips if not ip.startswith("127."))


def safe_filename(name):
    name = os.path.basename(name.replace("\\", "/")).strip()
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", name).strip(" .")
    return (name or "file")[-120:]


def unique_path(name):
    stem, ext = os.path.splitext(name)
    path = SAVE_DIR / name
    n = 1
    while path.exists():
        path = SAVE_DIR / f"{stem} ({n}){ext}"
        n += 1
    return path


class Handler(BaseHTTPRequestHandler):
    server_version = "PhotoDrop"

    def log_message(self, fmt, *args):
        pass

    # ---- helpers ----
    def is_local(self):
        return self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def send_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 10_000:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def deny_remote(self):
        if self.is_local():
            return False
        self.send_json(403, {"error": "この操作は Windows 本体からのみ可能です"})
        return True

    # ---- routing ----
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/":
            if self.is_local():
                self.send_html(RECEIVE_HTML)
            else:
                self.send_response(302)
                self.send_header("Location", "/send" + (f"?{url.query}" if url.query else ""))
                self.end_headers()
        elif url.path == "/send":
            self.send_html(SEND_HTML)
        elif url.path == "/api/status":
            if not self.deny_remote():
                self.status()
        elif url.path.startswith("/api/file/"):
            if not self.deny_remote():
                self.serve_file(url.path.rsplit("/", 1)[-1])
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/new":
            if not self.deny_remote():
                self.new_code()
        elif path == "/api/stop":
            if not self.deny_remote():
                self.stop()
        elif path == "/api/claim":
            self.claim()
        elif path == "/api/upload":
            self.upload()
        else:
            self.send_json(404, {"error": "not found"})

    # ---- receiver (Windows) ----
    def new_code(self):
        with lock:
            state["code"] = f"{secrets.randbelow(1_000_000):06d}"
            state["code_expires"] = time.time() + CODE_TTL
            state["attempts"] = 0
            state["token"] = None
            code = state["code"]
        self.send_json(200, {
            "code": code,
            "expires_in": CODE_TTL,
            "url": f"http://{lan_ip()}:{PORT}/send?code={code}",
        })

    def stop(self):
        with lock:
            state["code"] = None
            state["token"] = None
        self.send_json(200, {"ok": True})

    def status(self):
        now = time.time()
        with lock:
            if state["code"] and now > state["code_expires"]:
                state["code"] = None
            if state["token"] and now > state["token_expires"]:
                state["token"] = None
            files = [{"id": i, "name": f["name"], "size": f["size"], "time": f["time"]}
                     for i, f in enumerate(state["files"])]
            body = {
                "code": state["code"],
                "code_remaining": max(0, int(state["code_expires"] - now)) if state["code"] else 0,
                "connected": state["token"] is not None,
                "token_remaining": max(0, int(state["token_expires"] - now)) if state["token"] else 0,
                "files": files,
                "save_dir": str(SAVE_DIR),
            }
        self.send_json(200, body)

    def serve_file(self, file_id):
        with lock:
            try:
                f = state["files"][int(file_id)]
            except (ValueError, IndexError):
                f = None
        if not f or not f["path"].exists():
            self.send_json(404, {"error": "not found"})
            return
        # 画像と PDF だけブラウザで表示し、それ以外（HTML など）はダウンロード扱いにする
        ctype = mimetypes.guess_type(f["name"])[0] or ""
        inline = ctype in INLINE_TYPES
        self.send_response(200)
        self.send_header("Content-Type", ctype if inline else "application/octet-stream")
        self.send_header("Content-Length", str(f["path"].stat().st_size))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Disposition", ("inline" if inline else "attachment")
                         + "; filename*=UTF-8''" + urllib.parse.quote(f["name"]))
        self.end_headers()
        with open(f["path"], "rb") as src:
            shutil.copyfileobj(src, self.wfile)

    # ---- sender (iPhone) ----
    def claim(self):
        code = str(self.read_json().get("code", "")).strip()
        with lock:
            if not state["code"] or time.time() > state["code_expires"]:
                state["code"] = None
                self.send_json(403, {"error": "有効なパスワードがありません。Windows 側で発行し直してください"})
                return
            if not secrets.compare_digest(code, state["code"]):
                state["attempts"] += 1
                left = MAX_ATTEMPTS - state["attempts"]
                if left <= 0:
                    state["code"] = None
                    self.send_json(403, {"error": "間違いが多すぎるためパスワードを無効にしました。発行し直してください"})
                else:
                    self.send_json(403, {"error": f"パスワードが違います（あと {left} 回）"})
                return
            # 一度使ったパスワードは無効化し、送信用トークンに引き換える
            state["code"] = None
            state["token"] = secrets.token_urlsafe(32)
            state["token_expires"] = time.time() + TOKEN_TTL
            token = state["token"]
        self.send_json(200, {"token": token, "expires_in": TOKEN_TTL})

    def upload(self):
        token = self.headers.get("X-Token", "")
        with lock:
            valid = (state["token"] and time.time() <= state["token_expires"]
                     and secrets.compare_digest(token, state["token"]))
        if not valid:
            self.send_json(401, {"error": "送信期限が切れました。新しいパスワードを入力してください"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_FILE_SIZE:
            self.send_json(413, {"error": "ファイルサイズが不正です"})
            return

        name = safe_filename(urllib.parse.unquote(self.headers.get("X-Filename", "file")))
        SAVE_DIR.mkdir(parents=True, exist_ok=True)
        with lock:
            path = unique_path(name)
            path.touch()
        remaining = length
        try:
            with open(path, "wb") as out:
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        raise ConnectionError("upload interrupted")
                    out.write(chunk)
                    remaining -= len(chunk)
        except (OSError, ConnectionError):
            path.unlink(missing_ok=True)
            return
        with lock:
            state["files"].append({"name": path.name, "path": path, "size": length, "time": time.time()})
        print(f"受信: {path.name} ({length / 1024:.0f} KB)")
        self.send_json(200, {"ok": True, "name": path.name})


COMMON_CSS = """
:root { --bg:#f5f6f8; --card:#fff; --text:#1d1f23; --muted:#6b7280; --accent:#2563eb; --ok:#16a34a; --err:#dc2626; --border:#e5e7eb; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#111317; --card:#1b1e24; --text:#e8eaed; --muted:#9aa0a6; --accent:#60a5fa; --ok:#4ade80; --err:#f87171; --border:#2c3038; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,"Segoe UI","Hiragino Sans","Yu Gothic UI",sans-serif; }
main { max-width:720px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:1.4rem; margin:0 0 16px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:20px; margin-bottom:16px; }
button { font:inherit; border:0; border-radius:10px; padding:12px 18px; background:var(--accent); color:#fff; cursor:pointer; font-weight:600; }
button.secondary { background:transparent; color:var(--text); border:1px solid var(--border); }
button:disabled { opacity:.5; cursor:default; }
.muted { color:var(--muted); font-size:.9rem; }
.err { color:var(--err); }
.ok { color:var(--ok); }
"""

RECEIVE_HTML = """<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ファイル受信</title>
<style>""" + COMMON_CSS + """
.code { font-size:3.2rem; font-weight:700; letter-spacing:.3em; font-variant-numeric:tabular-nums; margin:8px 0; }
.row { display:flex; gap:20px; align-items:center; flex-wrap:wrap; }
#qr { background:#fff; padding:10px; border-radius:10px; line-height:0; }
#qr:empty { display:none; }
.url { word-break:break-all; font-family:ui-monospace,Consolas,monospace; font-size:.9rem; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:12px; }
.item { border:1px solid var(--border); border-radius:10px; overflow:hidden; text-decoration:none; color:inherit; }
.item img, .item .icon { width:100%; aspect-ratio:1; object-fit:cover; display:block; background:var(--border); }
.item .icon { display:flex; align-items:center; justify-content:center; font-size:3rem; }
.item div { padding:6px 8px; font-size:.8rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
</style></head><body><main>
<h1>📥 iPhone からファイルを受け取る</h1>
<div class="card">
  <div id="idle">
    <p>パスワードを発行して、iPhone で入力してください。</p>
    <button id="new">パスワードを発行</button>
  </div>
  <div id="active" hidden>
    <div class="row">
      <div>
        <div class="muted">ワンタイムパスワード</div>
        <div class="code" id="code"></div>
        <div class="muted" id="remain"></div>
      </div>
      <div id="qr"></div>
    </div>
    <p class="muted">iPhone で QR コードを読み取るか、次の URL を開いてください：</p>
    <p class="url" id="url"></p>
  </div>
  <div id="connected" hidden>
    <p class="ok"><b>✅ iPhone と接続中</b> — 送信されたファイルが下に表示されます</p>
    <p class="muted" id="tremain"></p>
  </div>
  <div style="margin-top:12px; display:flex; gap:8px;">
    <button id="renew" class="secondary" hidden>再発行</button>
    <button id="stop" class="secondary" hidden>終了</button>
  </div>
</div>
<div class="card">
  <b>受信したファイル</b> <span class="muted" id="count"></span>
  <p class="muted">保存先: <span id="dir"></span></p>
  <div class="grid" id="files"></div>
</div>
</main>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>
const $ = id => document.getElementById(id);
let shownFiles = 0, lastUrl = "";
const fmt = s => `${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;

async function issue() {
  const r = await fetch("/api/new", {method:"POST"});
  const d = await r.json();
  lastUrl = d.url;
  $("url").textContent = d.url;
  $("qr").innerHTML = "";
  if (window.QRCode) new QRCode($("qr"), {text:d.url, width:160, height:160});
  refresh();
}
$("new").onclick = issue;
$("renew").onclick = issue;
$("stop").onclick = async () => { await fetch("/api/stop", {method:"POST"}); refresh(); };

async function refresh() {
  let d;
  try { d = await (await fetch("/api/status")).json(); } catch { return; }
  $("idle").hidden = !!(d.code || d.connected);
  $("active").hidden = !d.code;
  $("connected").hidden = !d.connected;
  $("renew").hidden = $("stop").hidden = !(d.code || d.connected);
  if (d.code) { $("code").textContent = d.code; $("remain").textContent = "有効期限 残り " + fmt(d.code_remaining); }
  if (d.connected) $("tremain").textContent = "送信可能時間 残り " + fmt(d.token_remaining);
  $("dir").textContent = d.save_dir;
  $("count").textContent = d.files.length ? `(${d.files.length} 件)` : "";
  for (const f of d.files.slice(shownFiles)) {
    const a = document.createElement("a");
    a.className = "item"; a.href = `/api/file/${f.id}`; a.target = "_blank";
    let img;
    if (/\\.(jpe?g|png|gif|webp|bmp)$/i.test(f.name)) {
      img = document.createElement("img");
      img.src = `/api/file/${f.id}`; img.alt = ""; img.loading = "lazy";
    } else {
      img = document.createElement("span");
      img.className = "icon";
      img.textContent = /\\.pdf$/i.test(f.name) ? "📄" : /\\.(heic|heif)$/i.test(f.name) ? "🖼️" : /\\.(mov|mp4|m4v)$/i.test(f.name) ? "🎬" : "📦";
    }
    const cap = document.createElement("div");
    cap.textContent = f.name;
    a.append(img, cap);
    $("files").prepend(a);
  }
  shownFiles = d.files.length;
}
refresh();
setInterval(refresh, 1500);
</script></body></html>
"""

SEND_HTML = """<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ファイル送信</title>
<style>""" + COMMON_CSS + """
input[type=text] { font:inherit; font-size:2rem; letter-spacing:.3em; text-align:center; width:100%; padding:12px;
  border:1px solid var(--border); border-radius:10px; background:var(--bg); color:var(--text); }
button { width:100%; margin-top:12px; font-size:1.05rem; }
.pick { display:block; text-align:center; padding:28px 12px; border:2px dashed var(--border); border-radius:12px; cursor:pointer; }
.list { list-style:none; padding:0; margin:12px 0 0; }
.list li { display:flex; justify-content:space-between; gap:8px; padding:8px 0; border-bottom:1px solid var(--border); font-size:.9rem; }
.list li span:first-child { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
</style></head><body><main>
<h1>📤 Windows へファイルを送る</h1>
<div class="card" id="step1">
  <p>Windows に表示されている 6 桁のパスワードを入力してください。</p>
  <input type="text" id="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="000000">
  <button id="claim">接続</button>
  <p class="err" id="err1"></p>
</div>
<div class="card" id="step2" hidden>
  <p class="ok"><b>✅ 接続しました</b></p>
  <label class="pick">📎 タップして選ぶ<br><span class="muted">写真・PDF・その他のファイル</span><input type="file" id="files" multiple hidden></label>
  <ul class="list" id="list"></ul>
  <button id="send" disabled>送信</button>
  <p class="err" id="err2"></p>
</div>
</main>
<script>
const $ = id => document.getElementById(id);
let token = null;
try { token = sessionStorage.getItem("token"); } catch {}
const showStep2 = () => { $("step1").hidden = true; $("step2").hidden = false; };
const showStep1 = msg => {
  token = null; try { sessionStorage.removeItem("token"); } catch {}
  $("step1").hidden = false; $("step2").hidden = true; $("err1").textContent = msg || "";
};
if (token) showStep2();

async function claim() {
  $("err1").textContent = "";
  const code = $("code").value.trim();
  if (!/^\\d{6}$/.test(code)) { $("err1").textContent = "6 桁の数字を入力してください"; return; }
  $("claim").disabled = true;
  try {
    const r = await fetch("/api/claim", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({code})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    token = d.token; try { sessionStorage.setItem("token", token); } catch {}
    history.replaceState(null, "", "/send");
    showStep2();
  } catch (e) { $("err1").textContent = e.message || "接続できませんでした"; }
  $("claim").disabled = false;
}
$("claim").onclick = claim;
$("code").addEventListener("keydown", e => { if (e.key === "Enter") claim(); });
const preset = new URLSearchParams(location.search).get("code");
if (preset && !token) { $("code").value = preset; claim(); }

$("files").onchange = () => {
  $("list").innerHTML = "";
  for (const f of $("files").files) {
    const li = document.createElement("li");
    const n = document.createElement("span"); n.textContent = f.name;
    const s = document.createElement("span"); s.textContent = (f.size/1024/1024).toFixed(1) + " MB";
    li.append(n, s); $("list").append(li);
  }
  $("send").disabled = !$("files").files.length;
};

function uploadOne(file, el) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", "/api/upload");
    x.setRequestHeader("X-Token", token);
    x.setRequestHeader("X-Filename", encodeURIComponent(file.name));
    x.upload.onprogress = e => { if (e.lengthComputable) el.textContent = Math.round(e.loaded/e.total*100) + "%"; };
    x.onload = () => {
      let d = {}; try { d = JSON.parse(x.responseText); } catch {}
      if (x.status === 200) { el.textContent = "✅"; resolve(); }
      else { el.textContent = "❌"; const err = new Error(d.error || "送信失敗"); err.status = x.status; reject(err); }
    };
    x.onerror = () => { el.textContent = "❌"; reject(new Error("通信エラー")); };
    x.send(file);
  });
}

$("send").onclick = async () => {
  $("send").disabled = true; $("err2").textContent = "";
  const files = [...$("files").files];
  const marks = [...$("list").querySelectorAll("li span:last-child")];
  let ok = 0;
  for (let i = 0; i < files.length; i++) {
    try { await uploadOne(files[i], marks[i]); ok++; }
    catch (e) {
      if (e.status === 401) { showStep1(e.message); return; }
      $("err2").textContent = e.message;
    }
  }
  $("send").textContent = `送信完了 (${ok}/${files.length})`;
  setTimeout(() => { $("send").textContent = "送信"; }, 3000);
  $("files").value = "";
};
</script></body></html>
"""


def main():
    global PORT
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    server = None
    for port in [PORT] + [p for p in PORT_RANGE if p != PORT]:
        try:
            server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
            PORT = port
            break
        except OSError:
            print(f" ポート {port} は使用中のため、別のポートを試します")
    if server is None:
        raise SystemExit(" 使えるポートが見つかりませんでした")
    print("=" * 50)
    print(" ファイル受信サーバーを起動しました")
    print(f" Windows で開く : http://localhost:{PORT}")
    ips = all_ips()
    for ip in ips:
        print(f" iPhone で開く  : http://{ip}:{PORT}/send")
    if not ips:
        print(" ※ ネットワークに接続されていません。Wi-Fi かテザリングにつないでから起動し直してください")
    print(f" 保存先         : {SAVE_DIR}")
    print(" 終了するには、この画面を閉じるか Ctrl+C")
    print("=" * 50)
    try:
        import webbrowser
        webbrowser.open(f"http://localhost:{PORT}")
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    # ダブルクリックで起動したとき、エラーで画面がすぐ閉じないようにする
    try:
        main()
    except BaseException as e:
        if not isinstance(e, KeyboardInterrupt):
            import traceback
            traceback.print_exc()
            print()
            print(" エラーで停止しました。上のメッセージを確認してください。")
            try:
                input(" Enter キーを押すと閉じます")
            except (EOFError, KeyboardInterrupt):
                pass
