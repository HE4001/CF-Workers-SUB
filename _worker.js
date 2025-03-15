// ---------------------- 安全增强模块 ----------------------
// 生成加密安全的随机 TOKEN（大小写字母 + 数字）
function generateSecureToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const cryptoArray = new Uint8Array(length);
  crypto.getRandomValues(cryptoArray);
  return Array.from(cryptoArray, byte => chars[byte % chars.length]).join('');
}

// 初始化安全变量
let mytoken = generateSecureToken(); // 默认生成32位随机字符串
let guestToken = '';
let BotToken = '';
let ChatID = '';
let TG = 0;
let FileName = 'Secure-Sub';
let SUBUpdateTime = 6;
let total = 99; // TB
let timestamp = 4102329600000; // 过期时间戳

// 从环境变量初始化
let subConverter = "SUBAPI.cmliussss.net";
let subConfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini";
let subProtocol = 'https';

// ---------------------- 订阅源安全模块 ----------------------
// 域名白名单（通过环境变量配置）
const DEFAULT_ALLOWED_DOMAINS = [
  'raw.githubusercontent.com',
  'trusted-cdn.com'
];
const allowedDomains = env.ALLOWED_DOMAINS ? 
  env.ALLOWED_DOMAINS.split(',') : DEFAULT_ALLOWED_DOMAINS;

// 严格 URL 验证
function validateURL(urlString) {
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'https:' && 
           allowedDomains.some(d => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

// ---------------------- 安全日志模块 ----------------------
async function logSecurityEvent(type, request) {
  if (!BotToken || !ChatID) return;
  
  const safeIP = maskIP(request.headers.get('CF-Connecting-IP'));
  const safeUA = request.headers.get('User-Agent').slice(0, 50) + '...';
  
  const message = `#${type}\nIP: ${safeIP}\nUA: ${safeUA}`;
  await fetch(`https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&text=${encodeURIComponent(message)}`);
}

function maskIP(ip) {
  return ip.replace(/\.\d+\./, '.***.').replace(/(\w+):(\w+):.*/, '$1:$2::***');
}

// ---------------------- 基础工具函数 ----------------------
async function MD5MD5(text) {
  const encoder = new TextEncoder();
  const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstPass)).map(b => b.toString(16).padStart(2, '0')).join('');
  const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(secondPass)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function parseURLs(input) {
  return input.replace(/[\s"'\\r\\n]+/g, ',').split(',').filter(url => validateURL(url));
}

// ---------------------- 代理请求安全模块 ----------------------
async function safeFetch(url, options) {
  if (!validateURL(url)) throw new Error('非法请求地址');
  return fetch(url, {
    ...options,
    cf: {
      minify: { javascript: true, css: true, html: true },
      tls: { minVersion: 'TLSv1.3', verifyCertificate: true }
    }
  });
}
// ---------------------- 安全增强模块 ----------------------
// 生成加密安全的随机 TOKEN（大小写字母 + 数字）
function generateSecureToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const cryptoArray = new Uint8Array(length);
  crypto.getRandomValues(cryptoArray);
  return Array.from(cryptoArray, byte => chars[byte % chars.length]).join('');
}

// 初始化安全变量
let mytoken = generateSecureToken(); // 默认生成32位随机字符串
let guestToken = '';
let BotToken = '';
let ChatID = '';
let TG = 0;
let FileName = 'Secure-Sub';
let SUBUpdateTime = 6;
let total = 99; // TB
let timestamp = 4102329600000; // 过期时间戳

// 从环境变量初始化
let subConverter = "SUBAPI.cmliussss.net";
let subConfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini";
let subProtocol = 'https';

// ---------------------- 订阅源安全模块 ----------------------
// 域名白名单（通过环境变量配置）
const DEFAULT_ALLOWED_DOMAINS = [
  'raw.githubusercontent.com',
  'trusted-cdn.com'
];
const allowedDomains = env.ALLOWED_DOMAINS ? 
  env.ALLOWED_DOMAINS.split(',') : DEFAULT_ALLOWED_DOMAINS;

// 严格 URL 验证
function validateURL(urlString) {
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'https:' && 
           allowedDomains.some(d => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

// ---------------------- 安全日志模块 ----------------------
async function logSecurityEvent(type, request) {
  if (!BotToken || !ChatID) return;
  
  const safeIP = maskIP(request.headers.get('CF-Connecting-IP'));
  const safeUA = request.headers.get('User-Agent').slice(0, 50) + '...';
  
  const message = `#${type}\nIP: ${safeIP}\nUA: ${safeUA}`;
  await fetch(`https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&text=${encodeURIComponent(message)}`);
}

function maskIP(ip) {
  return ip.replace(/\.\d+\./, '.***.').replace(/(\w+):(\w+):.*/, '$1:$2::***');
}

// ---------------------- 基础工具函数 ----------------------
async function MD5MD5(text) {
  const encoder = new TextEncoder();
  const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstPass)).map(b => b.toString(16).padStart(2, '0')).join('');
  const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(secondPass)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function parseURLs(input) {
  return input.replace(/[\s"'\\r\\n]+/g, ',').split(',').filter(url => validateURL(url));
}

// ---------------------- 代理请求安全模块 ----------------------
async function safeFetch(url, options) {
  if (!validateURL(url)) throw new Error('非法请求地址');
  return fetch(url, {
    ...options,
    cf: {
      minify: { javascript: true, css: true, html: true },
      tls: { minVersion: 'TLSv1.3', verifyCertificate: true }
    }
  });
}
// ---------------------- HTML 界面模块 ----------------------
async function showSubscriptionEditor(env, url, guestToken) {
  const content = await env.KV.get('LINK.txt') || '';
  return new Response(buildEditorHTML(url, content, guestToken), {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

function buildEditorHTML(url, content, guestToken) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>${FileName} 订阅管理</title>
      <style>
        /* 样式表保持原有设计 */
        body { font-family: sans-serif; padding: 20px }
        .editor { 
          width: 80%; 
          height: 300px;
          border: 1px solid #ccc;
          padding: 10px 
        }
        .qrcode { margin: 20px 0 }
      </style>
      <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    </head>
    <body>
      <h2>订阅管理</h2>
      
      <!-- 订阅提交表单 -->
      <form id="subForm" onsubmit="return handleSubmit(event)">
        <input type="url" id="subUrl" placeholder="输入订阅链接" required>
        <select id="clientType">
          ${['clash', 'singbox', 'surge', 'quanx', 'loon']
            .map(c => `<option value="${c}">${c}</option>`).join('')}
        </select>
        <button type="submit">添加订阅</button>
      </form>

      <!-- 订阅编辑区域 -->
      <textarea class="editor" id="content">${content}</textarea>
      
      <!-- 订阅链接二维码 -->
      <div class="qrcode" id="qrcode"></div>

      <!-- 访客订阅区块 -->
      <div id="guestSub" style="display:none">
        <h3>访客订阅令牌: ${guestToken}</h3>
        <!-- 访客订阅二维码生成逻辑 -->
      </div>

      <script>
        // 表单提交处理
        async function handleSubmit(e) {
          e.preventDefault();
          const url = document.getElementById('subUrl').value;
          const client = document.getElementById('clientType').value;
          
          try {
            const res = await fetch(window.location.href, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ url, client })
            });
            if(res.ok) location.reload();
          } catch (error) {
            alert('提交失败: ' + error.message);
          }
        }

        // 二维码生成
        new QRCode(document.getElementById('qrcode'), {
          text: window.location.href,
          width: 200,
          height: 200
        });
      </script>
    </body>
    </html>
  `;
}

// ---------------------- KV 数据迁移模块 ----------------------
async function migrateKVData(env, filename) {
  const oldKey = `/${filename}`;
  const newKey = filename;
  
  const oldData = await env.KV.get(oldKey);
  const newData = await env.KV.get(newKey);
  
  if (oldData && !newData) {
    await env.KV.put(newKey, oldData);
    await env.KV.delete(oldKey);
  }
}

// ---------------------- 辅助工具模块 ----------------------
async function nginx() {
  return `
    <!DOCTYPE html>
    <html>
      <!-- 保持原有nginx欢迎页 -->
      <body>
        <h1>Welcome to nginx!</h1>
        ${env.URL ? `<p>正在跳转到安全页面...</p>` : ''}
      </body>
    </html>
  `;
}

async function fallbackToBase64(urls) {
  const rawData = urls.join('\n');
  return btoa(unescape(encodeURIComponent(rawData)));
}

// ---------------------- 代理与补丁模块 ----------------------
async function proxyURL(target, originalUrl) {
  const parsedTarget = new URL(target);
  const parsedOriginal = new URL(originalUrl);
  
  // 构建安全代理路径
  const safePath = `${parsedTarget.pathname}${parsedOriginal.search}`.replace('//', '/');
  
  return fetch(`${parsedTarget.origin}${safePath}`, {
    headers: { 
      'X-Forwarded-For': parsedOriginal.hostname,
      'User-Agent': 'Secure-Proxy/1.0'
    }
  });
}

function clashFix(content) {
  // WireGuard配置修复
  return content.replace(
    /(type: wireguard.*?)(, mtu: \d+)?$/gm, 
    '$1, remote-dns-resolve: true$2'
  );
}

// ---------------------- 中文兼容模块 ----------------------
// 保持原有ADD函数兼容性
async function ADD(input) {
  return input
    .replace(/[\s"'\\r\\n]+/g, ',')
    .split(',')
    .filter(item => validateURL(item.trim()));
}
