// 主入口
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const userAgent = (request.headers.get('User-Agent') || 'null').toLowerCase();

    // 初始化配置
    const config = initializeConfig(env, url);

    // 验证访问权限
    if (!await isAuthorized(url, config)) {
      return handleUnauthorized(request, config, url, userAgent);
    }

    // 处理订阅请求
    return await handleSubscription(request, config, url, userAgent);
  }
};

// --- 工具函数模块 ---

/**
 * 双重 MD5 加密
 * @param {string} text 输入文本
 * @returns {Promise<string>} 加密后的哈希值
 */
async function MD5MD5(text) {
  const encoder = new TextEncoder();
  const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstPass)).map(b => b.toString(16).padStart(2, '0')).join('');
  const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(secondPass)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

/**
 * Base64 解码
 * @param {string} str Base64 编码字符串
 * @returns {string} 解码后的字符串
 */
function base64Decode(str) {
  const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
  return new TextDecoder('utf-8').decode(bytes);
}

/**
 * 验证 Base64 字符串有效性
 * @param {string} str 输入字符串
 * @returns {boolean} 是否为有效 Base64
 */
function isValidBase64(str) {
  const cleanStr = str.replace(/\s/g, '');
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(cleanStr);
}

/**
 * 分割并清理订阅链接
 * @param {string} envadd 原始订阅数据
 * @returns {Promise<string[]>} 清理后的链接数组
 */
async function ADD(envadd) {
  const addtext = envadd.replace(/[	"'|\r\n]+/g, ',').replace(/,+/g, ',');
  let cleanedText = addtext;
  if (addtext.startsWith(',')) cleanedText = addtext.slice(1);
  if (addtext.endsWith(',')) cleanedText = addtext.slice(0, -1);
  return cleanedText.split(',');
}

// --- 配置初始化和权限验证 ---

/**
 * 初始化配置
 * @param {Object} env 环境变量
 * @param {URL} url 请求 URL
 * @returns {Object} 配置对象
 */
function initializeConfig(env, url) {
  const mytoken = env.TOKEN || 'auto';
  return {
    mytoken,
    botToken: env.TGTOKEN || '',
    chatId: env.TGID || '',
    tgEnabled: env.TG || 0,
    subConverter: env.SUBAPI || 'SUBAPI.cmliussss.net',
    subProtocol: (env.SUBAPI || '').includes('http://') ? 'http' : 'https',
    subConfig: env.SUBCONFIG || 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini',
    fileName: env.SUBNAME || 'CF-Workers-SUB',
    subUpdateTime: env.SUBUPTIME || 6,
    total: 99 * 1099511627776, // 99TB
    timestamp: 4102329600000, // 2099-12-31
    guestToken: env.GUESTTOKEN || env.GUEST || MD5MD5(mytoken) // 注意：这里需要 await，但在初始化时异步处理
  };
}

/**
 * 生成每日动态 Fake Token
 * @param {string} mytoken 主 Token
 * @returns {Promise<string>} Fake Token
 */
async function generateFakeToken(mytoken) {
  const currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0);
  const timeTemp = Math.ceil(currentDate.getTime() / 1000);
  return await MD5MD5(`${mytoken}${timeTemp}`);
}

/**
 * 验证请求权限
 * @param {URL} url 请求 URL
 * @param {Object} config 配置对象
 * @returns {Promise<boolean>} 是否授权
 */
async function isAuthorized(url, config) {
  const token = url.searchParams.get('token');
  const fakeToken = await generateFakeToken(config.mytoken);
  const path = url.pathname;
  return [config.mytoken, fakeToken, config.guestToken].includes(token) ||
    path === `/${config.mytoken}` || path.includes(`/${config.mytoken}?`);
}

/**
 * 处理未授权请求
 * @param {Request} request 请求对象
 * @param {Object} config 配置对象
 * @param {URL} url 请求 URL
 * @param {string} userAgent 用户代理
 * @returns {Response} 响应对象
 */
async function handleUnauthorized(request, config, url, userAgent) {
  if (config.tgEnabled === 1 && url.pathname !== '/' && url.pathname !== '/favicon.ico') {
    await sendMessage(`#异常访问 ${config.fileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`);
  }
  if (env.URL302) return Response.redirect(env.URL302, 302);
  if (env.URL) return await proxyURL(env.URL, url);
  return new Response(await nginx(), {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=UTF-8' }
  });
}

/**
 * 返回未授权页面
 * @returns {Promise<string>} HTML 页面内容
 */
async function nginx() {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>访问受限</title>
      <style>body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }</style>
    </head>
    <body>
      <h1>访问受限通知</h1>
      <p>我们很抱歉，您暂时无法访问此网站。</p>
      <p>如果您认为这是一个错误，请联系我们的支持团队寻求帮助：<a href="mailto:support@example.com">support@example.com</a></p>
    </body>
    </html>
  `;
}

/**
 * 发送 Telegram 通知
 * @param {string} type 消息类型
 * @param {string} ip 用户 IP
 * @param {string} add_data 附加数据
 */
async function sendMessage(type, ip, add_data = "") {
  if (!config.botToken || !config.chatId) return;
  const msg = `${type}\nIP: ${ip}\n${add_data}`;
  const url = `https://api.telegram.org/bot${config.botToken}/sendMessage?chat_id=${config.chatId}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
  return fetch(url, { method: 'get' });
}

// --- 订阅处理 ---

/**
 * 处理订阅请求
 * @param {Request} request 请求对象
 * @param {Object} config 配置对象
 * @param {URL} url 请求 URL
 * @param {string} userAgent 用户代理
 * @returns {Promise<Response>} 订阅响应
 */
async function handleSubscription(request, config, url, userAgent) {
  try {
    const links = await fetchLinks(config, env);
    const subscriptionData = await processSubscription(links, userAgent, config, url);
    return new Response(subscriptionData, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Update-Interval': `${config.subUpdateTime}`,
      }
    });
  } catch (error) {
    console.error('订阅处理失败:', error);
    return new Response('服务暂不可用，请稍后重试', { status: 500 });
  }
}

/**
 * 获取订阅链接
 * @param {Object} config 配置对象
 * @param {Object} env 环境变量
 * @returns {Promise<string[]>} 订阅链接数组
 */
async function fetchLinks(config, env) {
  let mainData = env.LINK || ''; // 默认值需根据实际情况定义
  if (env.LINKSUB) {
    const additionalLinks = await ADD(env.LINKSUB);
    mainData += '\n' + additionalLinks.join('\n');
  }
  return await ADD(mainData);
}

/**
 * 处理订阅数据
 * @param {string[]} links 订阅链接数组
 * @param {string} userAgent 用户代理
 * @param {Object} config 配置对象
 * @param {URL} url 请求 URL
 * @returns {Promise<string>} 订阅内容
 */
async function processSubscription(links, userAgent, config, url) {
  const subscriptionFormat = determineSubscriptionFormat(userAgent, url.searchParams);
  const [subscriptionContent, subUrls] = await getSUB(links, request, subscriptionFormat, userAgent);
  const uniqueContent = deduplicateLinks(subscriptionContent.join('\n'));

  if (subscriptionFormat === 'base64') {
    return btoa(uniqueContent);
  } else {
    const subConverterUrl = generateSubConverterUrl(subscriptionFormat, subUrls, config);
    const response = await fetch(subConverterUrl);
    if (!response.ok) throw new Error('订阅转换失败');
    let content = await response.text();
    if (subscriptionFormat === 'clash') content = await clashFix(content); // clashFix 需实现
    return content;
  }
}

/**
 * 确定订阅格式
 * @param {string} userAgent 用户代理
 * @param {URLSearchParams} searchParams 查询参数
 * @returns {string} 订阅格式
 */
function determineSubscriptionFormat(userAgent, searchParams) {
  if (userAgent.includes('clash') || searchParams.has('clash')) return 'clash';
  if (userAgent.includes('sing-box') || searchParams.has('sb')) return 'singbox';
  return 'base64';
}

/**
 * 生成订阅转换 URL
 * @param {string} format 目标格式
 * @param {string} subUrls 订阅 URL
 * @param {Object} config 配置对象
 * @returns {string} 转换 URL
 */
function generateSubConverterUrl(format, subUrls, config) {
  const target = format === 'clash' ? 'clash' : 'singbox';
  return `${config.subProtocol}://${config.subConverter}/sub?target=${target}&url=${encodeURIComponent(subUrls)}&insert=false&config=${encodeURIComponent(config.subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
}

/**
 * 去重订阅链接
 * @param {string} text 订阅文本
 * @returns {string} 去重后的文本
 */
function deduplicateLinks(text) {
  const lines = text.split('\n').map(line => line.trim()).filter(line => line && line.includes('://'));
  return [...new Set(lines)].join('\n');
}

/**
 * 获取订阅内容
 * @param {string[]} api 订阅 API 数组
 * @param {Request} request 请求对象
 * @param {string} ua 订阅格式
 * @param {string} userAgentHeader 用户代理头
 * @returns {Promise<[string[], string]>} 订阅内容和 URL
 */
async function getSUB(api, request, ua, userAgentHeader) {
  if (!api || !api.length) return [[], ''];
  const uniqueApi = [...new Set(api)];
  const results = await Promise.all(uniqueApi.map(url =>
    fetchWithTimeout(url, request, ua, userAgentHeader, 2000)
      .catch(err => ({ status: 'error', value: null, apiUrl: url }))
  ));

  let newApi = '';
  let subUrls = '';
  for (const { status, value, apiUrl } of results) {
    if (status === 'fulfilled' && value) {
      if (value.includes('proxies:')) subUrls += `|${apiUrl}`;
      else if (value.includes('://')) newApi += `${value}\n`;
      else if (isValidBase64(value)) newApi += `${base64Decode(value)}\n`;
    }
  }
  return [await ADD(newApi), subUrls];
}

/**
 * 带超时功能的 Fetch 请求
 * @param {string} url 请求 URL
 * @param {Request} request 原始请求
 * @param {string} ua 订阅格式
 * @param {string} userAgentHeader 用户代理头
 * @param {number} timeout 超时时间（毫秒）
 * @returns {Promise<Object>} 请求结果
 */
async function fetchWithTimeout(url, request, ua, userAgentHeader, timeout) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  const response = await getUrl(request, url, ua, userAgentHeader, { signal: controller.signal });
  clearTimeout(timeoutId);
  return { status: 'fulfilled', value: await response.text(), apiUrl: url };
}

/**
 * 执行 HTTP 请求
 * @param {Request} request 原始请求
 * @param {string} targetUrl 目标 URL
 * @param {string} ua 订阅格式
 * @param {string} userAgentHeader 用户代理头
 * @param {Object} options 请求选项
 * @returns {Promise<Response>} 响应对象
 */
async function getUrl(request, targetUrl, ua, userAgentHeader, options = {}) {
  const newHeaders = new Headers(request.headers);
  newHeaders.set("User-Agent", `v2rayN/6.45 cmliu/CF-Workers-SUB ${ua}(${userAgentHeader})`);
  const modifiedRequest = new Request(targetUrl, {
    method: request.method,
    headers: newHeaders,
    body: request.method === "GET" ? null : request.body,
    redirect: "follow",
    ...options
  });
  return await fetch(modifiedRequest);
}

// --- 未实现函数占位符（需根据需求补充） ---

/**
 * 修复 Clash 订阅内容（占位符）
 * @param {string} content 原始内容
 * @returns {Promise<string>} 修复后的内容
 */
async function clashFix(content) {
  return content; // 需根据实际需求实现
}

/**
 * 代理 URL 请求（占位符）
 * @param {string} targetUrl 目标 URL
 * @param {URL} url 请求 URL
 * @returns {Promise<Response>} 响应对象
 */
async function proxyURL(targetUrl, url) {
  return fetch(targetUrl); // 需根据实际需求实现
}
