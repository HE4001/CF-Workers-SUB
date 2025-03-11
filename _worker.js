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
    const additionalLinks = await ADD
