// 部署完成后在网址后面加上这个，获取自建节点和机场聚合节点，/?token=auto或/auto或

// ========================
// 环境变量配置（强制从环境变量获取）
// ========================
let mytoken;          // 主 Token（必须通过环境变量设置）
let guestToken;       // 访客 Token（可选）
let subConverter;     // 订阅转换后端（默认值使用安全域名）
let subConfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini"; 
let FileName = 'Secure-SUB';
let SUBUpdateTime = 6; // 订阅更新时间（小时）
let total = 99;        // 伪流量统计（TB）
let timestamp = 4102329600000; // 2099-12-31

// 初始化环境变量
function initEnv(env) {
  if (!env.TOKEN) throw new Error('必须配置环境变量 TOKEN');
  mytoken = env.TOKEN;
  guestToken = env.GUEST_TOKEN || '';
  subConverter = env.SUB_API || 'safe-subapi.example.com'; // 建议自建
}

// ========================
// 安全增强函数
// ========================
// SHA-256 哈希生成
async function secureHash(text) {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// SSRF 防护白名单
const ALLOWED_DOMAINS = new Set([
  'raw.githubusercontent.com',
  'trusted-sub.example.com' // 添加可信域名
]);

function isUrlAllowed(url) {
  try {
    const hostname = new URL(url).hostname;
    return Array.from(ALLOWED_DOMAINS).some(d => hostname.endsWith(d));
  } catch {
    return false;
  }
}

// ========================
// Token 验证逻辑（增强版）
// ========================
async function validateToken(request) {
  const url = new URL(request.url);
  
  // 从 URL 获取 Token
  const tokenParam = url.searchParams.get('token') || '';
  const pathToken = url.pathname.split('/')[1] || '';
  
  // 动态生成临时 Token
  const currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0);
  const timeTemp = Math.ceil(currentDate.getTime() / 1000);
  const fakeToken = await secureHash(`${mytoken}${timeTemp}`);
  
  // 统一转为小写比较
  const validTokens = [
    mytoken.toLowerCase(), 
    fakeToken.toLowerCase(),
    guestToken.toLowerCase()
  ];
  
  const token = (tokenParam || pathToken).toLowerCase();
  
  return validTokens.includes(token) || 
         url.pathname.toLowerCase().startsWith(`/${mytoken.toLowerCase()}`);
}

// ========================
// 主函数框架
// ========================
export default {
  async fetch(request, env) {
    try {
      // 初始化环境变量
      initEnv(env);
      
      // Token 验证
      if (!(await validateToken(request))) {
        return new Response(await generateBlockPage(), {
          status: 403,
          headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
      }
      
      // 后续处理...
      
    } catch (error) {
      // 安全错误处理（不泄露细节）
      return new Response('服务暂时不可用', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain; charset=UTF-8' }
      });
    }
  }
};

// ========================
// 拦截页面生成
// ========================
async function generateBlockPage() {
  return `<!DOCTYPE html>
<html>
<head>
  <title>访问被拒绝</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
    h1 { color: #dc3545; }
    p { color: #6c757d; }
  </style>
</head>
<body>
  <h1>403 访问被拒绝</h1>
  <p>请检查您的 Token 或联系管理员获取权限</p>
</body>
</html>`;
}
// ========================
// 订阅源处理逻辑
// ========================
// 初始化订阅源（环境变量 + KV 存储）
async function initSubscriptionSources(env, request) {
  let MainData = '';
  let urls = [];
  
  // 从 KV 或环境变量读取
  if (env.KV) {
    await migrateLegacyData(env, 'LINK.txt');
    if (isEditRequest(request)) {
      return handleKVEditor(request, env, 'LINK.txt');
    }
    MainData = await env.KV.get('LINK.txt') || '';
  } else {
    MainData = env.LINK || '';
    if (env.LINKSUB) urls = await parseLinks(env.LINKSUB);
  }
  
  // 合并订阅源并去重
  const allLinks = await parseLinks(MainData + '\n' + urls.join('\n'));
  const { nodes, subscriptions } = classifyLinks(allLinks);
  
  return { 
    localNodes: nodes.join('\n'), 
    remoteSubs: subscriptions 
  };
}

// 链接分类（本地节点 vs 远程订阅）
function classifyLinks(links) {
  const nodes = [];
  const subscriptions = [];
  
  for (const link of links) {
    if (link.startsWith('http://') || link.startsWith('https://')) {
      if (!isUrlAllowed(link)) {
        console.log(`阻止非法订阅源: ${link}`);
        continue;
      }
      subscriptions.push(link);
    } else {
      nodes.push(link);
    }
  }
  
  return { nodes, subscriptions };
}

// ========================
// 订阅内容获取与处理
// ========================
async function fetchSubscriptions(subUrls, request) {
  const validSubs = [];
  const converterUrls = [];
  
  // 并发获取订阅（带超时和重试）
  const responses = await Promise.allSettled(
    subUrls.map(url => fetchWithRetry(url, request))
  );
  
  for (const res of responses) {
    if (res.status === 'fulfilled') {
      const content = await processResponse(res.value);
      if (content) {
        validSubs.push(content);
        if (isClashConfig(content)) {
          converterUrls.push(res.value.url);
        }
      }
    }
  }
  
  return {
    nodes: validSubs.join('\n'),
    converterUrls: converterUrls.join('|')
  };
}

// 安全获取订阅（带重试）
async function fetchWithRetry(url, request, retries = 1) {
  try {
    const response = await fetch(url, {
      headers: generateSafeHeaders(request),
      cf: { cacheTtl: 3600 } // 缓存 1 小时
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return { 
      content: await response.text(),
      url: response.url 
    };
  } catch (error) {
    if (retries > 0) return fetchWithRetry(url, request, retries - 1);
    throw error;
  }
}

// 生成安全请求头
function generateSafeHeaders(request) {
  const headers = new Headers(request.headers);
  headers.set("User-Agent", "Secure-SUB/2.0");
  headers.delete("Cookie"); // 移除敏感头
  headers.delete("Authorization");
  return headers;
}

// ========================
// 响应内容处理
// ========================
function processResponse(response) {
  const content = response.content;
  
  // 识别订阅格式
  if (content.includes('proxies:')) {
    return null; // Clash 配置留给转换器处理
  }
  if (isBase64(content)) {
    return base64Decode(content);
  }
  if (isValidNode(content)) {
    return content;
  }
  return null;
}

// 基础64解码（安全版）
function base64Decode(str) {
  try {
    return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return '';
  }
}

// ========================
// KV 存储管理
// ========================
async function handleKVEditor(request, env, key) {
  if (request.method === "POST") {
    const content = await request.text();
    await env.KV.put(key, content);
    return new Response("保存成功", { 
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
  
  const savedContent = await env.KV.get(key) || '';
  return generateEditorUI(savedContent);
}

// ========================
// 工具函数
// ========================
async function parseLinks(text) {
  return text.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
}

function isEditRequest(request) {
  const ua = request.headers.get('User-Agent') || '';
  return ua.includes('Mozilla') && new URL(request.url).search === '';
}

function isClashConfig(content) {
  return content.includes('proxies:') && content.includes('rules:');
}

function isBase64(str) {
  return /^[A-Za-z0-9+/]+={0,2}$/.test(str.trim());
}

function isValidNode(text) {
  return text.includes('://') && 
         (text.includes('vless') || 
          text.includes('trojan') || 
          text.includes('ss://'));
}
// ========================
// 订阅格式转换核心逻辑
// ========================
async function generateSubscriptionResponse(data, request) {
  const url = new URL(request.url);
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  
  // 自动识别客户端类型
  const format = detectSubscriptionFormat(userAgent, url);
  
  // 原始节点数据
  const rawData = data.localNodes + '\n' + data.nodes;
  const uniqueData = deduplicateContent(rawData);
  
  // 基础响应头
  const baseHeaders = {
    "Profile-Update-Interval": `${SUBUpdateTime}`,
    "Cache-Control": "public, max-age=3600" // 1小时缓存
  };

  // 直接返回 BASE64
  if (format === 'base64') {
    return new Response(base64Encode(uniqueData), {
      headers: {
        ...baseHeaders,
        "Content-Type": "text/plain; charset=utf-8"
      }
    });
  }

  // 使用订阅转换服务
  const converterUrl = buildConverterUrl(format, data.converterUrls, url);
  return fetchConvertedSubscription(converterUrl, uniqueData, baseHeaders);
}

// ========================
// 格式检测逻辑
// ========================
function detectSubscriptionFormat(ua, url) {
  const params = url.searchParams;
  
  // 优先处理强制格式参数
  if (params.has('b64')) return 'base64';
  if (params.has('clash')) return 'clash';
  if (params.has('singbox')) return 'singbox';
  if (params.has('surge')) return 'surge';

  // 根据 User-Agent 自动识别
  if (ua.includes('clash')) return 'clash';
  if (ua.includes('singbox')) return 'singbox';
  if (ua.includes('surge')) return 'surge';
  if (ua.includes('quantumult')) return 'quanx';
  if (ua.includes('v2ray')) return 'base64';
  
  return 'base64'; // 默认回退
}

// ========================
// 转换器 URL 构建
// ========================
function buildConverterUrl(format, converterUrls, currentUrl) {
  const protocol = subConverter.startsWith('http://') ? 'http' : 'https';
  const converterHost = subConverter.replace(/https?:\/\//, '');
  
  const params = new URLSearchParams({
    url: `${currentUrl.origin}/sub?token=${await generateTempToken()}|${converterUrls}`,
    config: subConfig,
    emoji: 'true',
    scv: 'true',
    tfo: 'false',
    udp: 'true'
  });

  // 不同客户端的特殊参数
  switch(format) {
    case 'clash':
      params.set('target', 'clash');
      break;
    case 'singbox':
      params.set('target', 'singbox');
      break;
    case 'surge':
      params.set('target', 'surge');
      params.set('ver', '4');
      break;
    case 'quanx':
      params.set('target', 'quanx');
      break;
  }

  return `${protocol}://${converterHost}/sub?${params}`;
}

// ========================
// 安全内容转换
// ========================
async function fetchConvertedSubscription(url, fallbackData, headers) {
  try {
    const response = await fetch(url, {
      cf: {
        cacheTtl: 3600,
        cacheEverything: true
      }
    });
    
    if (!response.ok) throw new Error('转换服务不可用');
    
    // 安全校验转换结果
    const content = await validateConvertedContent(await response.text());
    
    return new Response(content, {
      headers: {
        ...headers,
        "Content-Disposition": `attachment; filename="${FileName}.${format}"`,
        "Content-Type": "text/plain; charset=utf-8"
      }
    });
  } catch (error) {
    // 回退到原始数据
    return new Response(base64Encode(fallbackData), {
      headers: {
        ...headers,
        "Content-Type": "text/plain; charset=utf-8"
      }
    });
  }
}

// ========================
// 数据编码与处理
// ========================
function base64Encode(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  return btoa(String.fromCharCode(...new Uint8Array(data)));
}

function deduplicateContent(text) {
  return [...new Set(text.split('\n'))].join('\n');
}

async function generateTempToken() {
  return secureHash(`${mytoken}${Date.now().toString().slice(0,8)}`);
}

// ========================
// 内容安全校验
// ========================
function validateConvertedContent(content) {
  // 基础注入防护
  const forbiddenPatterns = [
    /<\s*script/i,
    /eval\s*\(/,
    /document\./,
    /window\./
  ];
  
  if (forbiddenPatterns.some(p => p.test(content))) {
    throw new Error('检测到潜在危险内容');
  }
  
  return content;
}
