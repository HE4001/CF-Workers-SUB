// CF-Workers-SUB - 重构版本
// 增强安全性，保持原有功能，移除Telegram相关功能

// 配置管理
class Config {
    constructor(env = {}) {
        this.token = env.TOKEN || 'auto';
        this.guestToken = env.GUESTTOKEN || env.GUEST || '';
        this.fileName = env.SUBNAME || 'CF-Workers-SUB';
        this.updateInterval = parseInt(env.SUBUPTIME) || 6;
        this.subConverter = env.SUBAPI || 'SUBAPI.cmliussss.net';
        this.subConfig = env.SUBCONFIG || 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini';
        this.mainData = env.LINK || 'https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray';
        this.linkSub = env.LINKSUB || '';
        this.url302 = env.URL302 || '';
        this.proxyUrl = env.URL || '';
        this.warpNodes = env.WARP || '';
        
        // 处理协议
        this.subProtocol = this.subConverter.includes('http://') ? 'http' : 'https';
        this.subConverter = this.subConverter.replace(/^https?:\/\//, '');
        
        // 安全常量
        this.TOTAL_BYTES = 99 * 1099511627776; // 99TB
        this.EXPIRE_TIMESTAMP = 4102329600000; // 2099-12-31
        this.REQUEST_TIMEOUT = 3000;
        this.MAX_CONTENT_SIZE = 10 * 1024 * 1024; // 10MB
        this.CACHE_TTL = 300000; // 5分钟
    }
}

// 安全工具类
class SecurityUtils {
    static async doubleMD5(text) {
        const encoder = new TextEncoder();
        const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
        const firstArray = Array.from(new Uint8Array(firstHash));
        const firstHex = firstArray.map(b => b.toString(16).padStart(2, '0')).join('');
        const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
        const secondArray = Array.from(new Uint8Array(secondHash));
        const secondHex = secondArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return secondHex.toLowerCase();
    }

    static sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input
            .replace(/[<>\"'&]/g, (char) => {
                const entities = { '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;' };
                return entities[char] || char;
            })
            .slice(0, 1000);
    }

    static validateRequest(request) {
        // 基础请求验证
        const url = new URL(request.url);
        const userAgent = request.headers.get('User-Agent') || '';
        
        // 防止恶意请求
        if (userAgent.length > 500) return false;
        if (url.pathname.length > 200) return false;
        
        return true;
    }

    static validateCSRF(request) {
        if (request.method === 'GET') return true;
        
        const referer = request.headers.get('Referer');
        const origin = request.headers.get('Origin');
        const host = request.headers.get('Host');
        
        if (!referer && !origin) return false;
        
        const referDomain = referer ? new URL(referer).hostname : null;
        const originDomain = origin ? new URL(origin).hostname : null;
        
        return referDomain === host || originDomain === host;
    }
}

// 验证工具类
class ValidationUtils {
    static isValidBase64(str) {
        if (!str || typeof str !== 'string') return false;
        const cleanStr = str.replace(/\s/g, '');
        const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
        return base64Regex.test(cleanStr) && cleanStr.length % 4 === 0;
    }

    static isValidUrl(str) {
        try {
            const url = new URL(str);
            return ['http:', 'https:'].includes(url.protocol);
        } catch {
            return false;
        }
    }

    static validateContent(content) {
        if (!content || typeof content !== 'string') {
            return { isValid: false, error: 'Content is empty or invalid' };
        }
        if (content.length > 10 * 1024 * 1024) {
            return { isValid: false, error: 'Content too large' };
        }
        return { isValid: true };
    }
}

// 缓存管理
class CacheManager {
    constructor() {
        this.cache = new Map();
        this.defaultTTL = 300000; // 5分钟
    }

    set(key, value, ttl = null) {
        const expires = Date.now() + (ttl || this.defaultTTL);
        this.cache.set(key, { value, expires });
    }

    get(key) {
        const item = this.cache.get(key);
        if (!item || Date.now() > item.expires) {
            this.cache.delete(key);
            return null;
        }
        return item.value;
    }

    cleanup() {
        const now = Date.now();
        for (const [key, item] of this.cache.entries()) {
            if (now > item.expires) {
                this.cache.delete(key);
            }
        }
    }
}

// 订阅处理类
class SubscriptionProcessor {
    constructor(config, cache) {
        this.config = config;
        this.cache = cache;
    }

    async processData(data) {
        if (!data) return [];
        
        return data
            .replace(/[\t"'|\r\n]+/g, '\n')
            .replace(/\n+/g, '\n')
            .trim()
            .split('\n')
            .filter(line => line.trim())
            .filter(line => line.length < 2000); // 防止超长行
    }

    async fetchSubscriptions(urls, request, userAgent) {
        if (!urls || urls.length === 0) return { content: [], convertUrls: '' };

        const uniqueUrls = [...new Set(urls)]
            .filter(url => url?.trim?.())
            .filter(url => ValidationUtils.isValidUrl(url))
            .slice(0, 50); // 限制最大订阅数量

        const cacheKey = `sub_${this.hashUrls(uniqueUrls)}`;
        const cached = this.cache.get(cacheKey);
        if (cached) return cached;

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.config.REQUEST_TIMEOUT);

        try {
            const promises = uniqueUrls.map(url => this.fetchSingleSubscription(url, request, userAgent, controller.signal));
            const results = await Promise.allSettled(promises);
            const processed = await this.processResults(results, uniqueUrls);
            
            this.cache.set(cacheKey, processed, 180000); // 3分钟缓存
            return processed;
        } finally {
            clearTimeout(timeout);
        }
    }

    async fetchSingleSubscription(url, request, userAgent, signal) {
        const headers = new Headers();
        headers.set('User-Agent', `v2rayN/6.45 CF-Workers-SUB/2.0 (${userAgent})`);
        headers.set('Accept', 'text/plain,text/html,application/json');

        const response = await fetch(url, {
            method: 'GET',
            headers,
            signal,
            cf: { timeout: this.config.REQUEST_TIMEOUT }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const content = await response.text();
        if (content.length > this.config.MAX_CONTENT_SIZE) {
            throw new Error('Content too large');
        }

        return { url, content, status: 'success' };
    }

    async processResults(results, urls) {
        let content = [];
        let convertUrls = '';

        for (let i = 0; i < results.length; i++) {
            const result = results[i];
            const url = urls[i];

            if (result.status === 'fulfilled') {
                const data = result.value.content;
                
                if (this.isClashConfig(data)) {
                    convertUrls += `|${url}`;
                } else if (this.isSingboxConfig(data)) {
                    convertUrls += `|${url}`;
                } else if (ValidationUtils.isValidBase64(data.replace(/\s/g, ''))) {
                    try {
                        const decoded = this.decodeBase64(data);
                        content.push(...await this.processData(decoded));
                    } catch (e) {
                        console.warn('Base64 decode failed:', url);
                    }
                } else if (this.isPlainTextNodes(data)) {
                    content.push(...await this.processData(data));
                }
            }
        }

        return { content, convertUrls };
    }

    isClashConfig(content) {
        return content.includes('proxies:');
    }

    isSingboxConfig(content) {
        return content.includes('"outbounds"') && content.includes('"inbounds"');
    }

    isPlainTextNodes(content) {
        return /^[a-z0-9+/]+:\/\//im.test(content);
    }

    decodeBase64(str) {
        try {
            return atob(str.replace(/\s/g, ''));
        } catch (e) {
            // 兜底解码
            const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
            return new TextDecoder('utf-8').decode(bytes);
        }
    }

    hashUrls(urls) {
        return btoa(urls.join('|')).slice(0, 16);
    }
}

// 格式转换类
class FormatConverter {
    constructor(config) {
        this.config = config;
    }

    detectFormat(userAgent, searchParams) {
        // URL参数优先
        if (searchParams.has('base64') || searchParams.has('b64')) return 'base64';
        if (searchParams.has('clash')) return 'clash';
        if (searchParams.has('singbox') || searchParams.has('sb')) return 'singbox';
        if (searchParams.has('surge')) return 'surge';
        if (searchParams.has('quanx')) return 'quanx';
        if (searchParams.has('loon')) return 'loon';

        // User-Agent检测
        const ua = userAgent.toLowerCase();
        if (ua.includes('sing-box') || ua.includes('singbox')) return 'singbox';
        if (ua.includes('surge')) return 'surge';
        if (ua.includes('quantumult')) return 'quanx';
        if (ua.includes('loon')) return 'loon';
        if (ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')) return 'clash';

        return 'base64';
    }

    async convert(content, format, subscriptionUrl) {
        if (format === 'base64') {
            return this.encodeBase64(content);
        }

        const converterUrl = this.buildConverterUrl(format, subscriptionUrl);
        if (!converterUrl) return this.encodeBase64(content);

        try {
            const response = await fetch(converterUrl, {
                cf: { timeout: 10000 }
            });

            if (!response.ok) throw new Error(`Converter error: ${response.status}`);

            let result = await response.text();
            if (format === 'clash') {
                result = this.fixClashConfig(result);
            }
            
            return result;
        } catch (error) {
            console.warn('Conversion failed, fallback to base64:', error.message);
            return this.encodeBase64(content);
        }
    }

    buildConverterUrl(format, subscriptionUrl) {
        const baseUrl = `${this.config.subProtocol}://${this.config.subConverter}/sub`;
        const params = new URLSearchParams({
            url: subscriptionUrl,
            insert: 'false',
            config: this.config.subConfig,
            emoji: 'true',
            list: 'false',
            tfo: 'false',
            scv: 'true',
            fdn: 'false',
            sort: 'false',
            new_name: 'true'
        });

        const targets = {
            clash: 'clash',
            singbox: 'singbox',
            surge: 'surge',
            quanx: 'quanx',
            loon: 'loon'
        };

        if (!targets[format]) return null;
        
        params.set('target', targets[format]);
        if (format === 'surge') params.set('ver', '4');
        if (format === 'quanx') params.set('udp', 'true');

        return `${baseUrl}?${params.toString()}`;
    }

    encodeBase64(content) {
        try {
            return btoa(unescape(encodeURIComponent(content)));
        } catch (e) {
            // 兜底编码
            const encoder = new TextEncoder();
            const bytes = encoder.encode(content);
            let result = '';
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
            
            for (let i = 0; i < bytes.length; i += 3) {
                const a = bytes[i] || 0;
                const b = bytes[i + 1] || 0;
                const c = bytes[i + 2] || 0;
                
                result += chars[a >> 2];
                result += chars[((a & 3) << 4) | (b >> 4)];
                result += chars[((b & 15) << 2) | (c >> 6)];
                result += chars[c & 63];
            }
            
            const padding = (3 - (bytes.length % 3)) % 3;
            return result.slice(0, result.length - padding) + '='.repeat(padding);
        }
    }

    fixClashConfig(content) {
        return content.replace(
            /, mtu: 1280, udp: true/g,
            ', mtu: 1280, remote-dns-resolve: true, udp: true'
        );
    }
}

// KV存储处理
class StorageHandler {
    constructor(config) {
        this.config = config;
    }

    async handleKVRequest(request, env, guestToken) {
        const url = new URL(request.url);
        
        if (request.method === 'POST') {
            return await this.handleSave(request, env);
        }
        
        const content = await this.loadContent(env);
        const html = this.generateEditorHTML(url, content, guestToken, !!env.KV, request.headers.get('User-Agent'));
        
        return new Response(html, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    async handleSave(request, env) {
        if (!env.KV) {
            return new Response('KV namespace not bound', { status: 400 });
        }

        if (!SecurityUtils.validateCSRF(request)) {
            return new Response('CSRF validation failed', { status: 403 });
        }

        try {
            const content = await request.text();
            const validation = ValidationUtils.validateContent(content);
            
            if (!validation.isValid) {
                return new Response(validation.error, { status: 400 });
            }

            await env.KV.put('LINK.txt', content);
            return new Response('保存成功');
        } catch (error) {
            console.error('Save error:', error);
            return new Response(`保存失败: ${error.message}`, { status: 500 });
        }
    }

    async loadContent(env) {
        if (!env.KV) return '';
        
        try {
            return await env.KV.get('LINK.txt') || '';
        } catch (error) {
            console.error('Load error:', error);
            return `读取数据时发生错误: ${error.message}`;
        }
    }

    generateEditorHTML(url, content, guestToken, hasKV, userAgent) {
        const safeName = SecurityUtils.sanitizeInput(this.config.fileName);
        const safeToken = SecurityUtils.sanitizeInput(this.config.token);
        const safeGuest = SecurityUtils.sanitizeInput(guestToken);
        
        return `<!DOCTYPE html>
<html>
<head>
    <title>${safeName} 订阅编辑</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="${safeToken}">
    <style>
        * { box-sizing: border-box; }
        body { margin: 0; padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2em; }
        .content { padding: 30px; }
        .subscription-links { margin-bottom: 30px; }
        .link-group { margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 6px; border-left: 4px solid #007bff; }
        .link-group h3 { margin: 0 0 10px 0; color: #007bff; font-size: 1.1em; }
        .subscription-link { display: block; color: #007bff; text-decoration: none; padding: 8px 12px; background: white; border-radius: 4px; margin: 5px 0; border: 1px solid #dee2e6; transition: all 0.2s; }
        .subscription-link:hover { background: #e3f2fd; border-color: #007bff; }
        .qr-container { margin: 10px 0; min-height: 100px; }
        .editor-section { margin-top: 30px; padding-top: 30px; border-top: 2px solid #dee2e6; }
        .editor { width: 100%; height: 400px; padding: 15px; border: 2px solid #dee2e6; border-radius: 6px; font-family: 'Monaco', 'Menlo', monospace; font-size: 13px; line-height: 1.5; resize: vertical; }
        .editor:focus { outline: none; border-color: #007bff; box-shadow: 0 0 0 3px rgba(0,123,255,0.25); }
        .button-group { margin-top: 15px; display: flex; gap: 10px; align-items: center; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; transition: all 0.2s; }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .status { margin-left: 10px; font-size: 14px; color: #666; }
        .toggle-section { margin: 20px 0; }
        .toggle-btn { background: none; border: none; color: #007bff; cursor: pointer; font-size: 16px; text-decoration: underline; }
        .toggle-content { margin-top: 15px; }
        .config-info { background: #e7f3ff; padding: 15px; border-radius: 6px; margin: 20px 0; }
        .config-info h4 { margin: 0 0 10px 0; color: #0066cc; }
        .hidden { display: none; }
        @media (max-width: 768px) {
            body { padding: 10px; }
            .content { padding: 20px; }
            .header { padding: 20px; }
            .header h1 { font-size: 1.5em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 ${safeName}</h1>
            <p>订阅聚合管理面板</p>
        </div>
        
        <div class="content">
            <div class="subscription-links">
                <h2>📡 订阅地址</h2>
                
                <div class="link-group">
                    <h3>管理员订阅</h3>
                    <a href="javascript:void(0)" onclick="copyAndQR('https://${url.hostname}/${safeToken}','qr_admin_0')" class="subscription-link">
                        🔄 自适应: https://${url.hostname}/${safeToken}
                    </a>
                    <div id="qr_admin_0" class="qr-container"></div>
                    
                    <a href="javascript:void(0)" onclick="copyAndQR('https://${url.hostname}/${safeToken}?b64','qr_admin_1')" class="subscription-link">
                        📝 Base64: https://${url.hostname}/${safeToken}?b64
                    </a>
                    <div id="qr_admin_1" class="qr-container"></div>
                    
                    <a href="javascript:void(0)" onclick="copyAndQR('https://${url.hostname}/${safeToken}?clash','qr_admin_2')" class="subscription-link">
                        ⚡ Clash: https://${url.hostname}/${safeToken}?clash
                    </a>
                    <div id="qr_admin_2" class="qr-container"></div>
                </div>

                <div class="toggle-section">
                    <button class="toggle-btn" onclick="toggleGuest()">🔓 查看访客订阅</button>
                    <div id="guestSection" class="toggle-content hidden">
                        <div class="link-group">
                            <h3>访客订阅 (只读)</h3>
                            <p><strong>访客TOKEN:</strong> ${safeGuest}</p>
                            
                            <a href="javascript:void(0)" onclick="copyAndQR('https://${url.hostname}/sub?token=${safeGuest}','qr_guest_0')" class="subscription-link">
                                🔄 自适应: https://${url.hostname}/sub?token=${safeGuest}
                            </a>
                            <div id="qr_guest_0" class="qr-container"></div>
                            
                            <a href="javascript:void(0)" onclick="copyAndQR('https://${url.hostname}/sub?token=${safeGuest}&b64','qr_guest_1')" class="subscription-link">
                                📝 Base64: https://${url.hostname}/sub?token=${safeGuest}&b64
                            </a>
                            <div id="qr_guest_1" class="qr-container"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="config-info">
                <h4>⚙️ 当前配置</h4>
                <p><strong>转换后端:</strong> ${this.config.subProtocol}://${this.config.subConverter}</p>
                <p><strong>配置文件:</strong> ${this.config.subConfig}</p>
                <p><strong>更新间隔:</strong> ${this.config.updateInterval} 小时</p>
            </div>

            ${hasKV ? `
            <div class="editor-section">
                <h3>📝 订阅内容编辑</h3>
                <textarea class="editor" id="content" placeholder="请输入订阅链接或节点信息，每行一个...">${SecurityUtils.sanitizeInput(content)}</textarea>
                <div class="button-group">
                    <button class="btn btn-primary" onclick="saveContent(this)">💾 保存</button>
                    <span class="status" id="saveStatus"></span>
                </div>
            </div>
            ` : '<div class="config-info"><p>⚠️ 请绑定 KV 命名空间以启用编辑功能</p></div>'}
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
    <script>
        function copyAndQR(text, containerId) {
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ 已复制到剪贴板');
            }).catch(() => {
                // 兜底复制方案
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('✅ 已复制到剪贴板');
            });

            const container = document.getElementById(containerId);
            if (container && window.QRCode) {
                container.innerHTML = '';
                QRCode.toCanvas(container, text, {
                    width: 200,
                    margin: 2,
                    color: { dark: '#000000', light: '#ffffff' }
                }, (error) => {
                    if (error) console.error('QR生成失败:', error);
                });
            }
        }

        function toggleGuest() {
            const section = document.getElementById('guestSection');
            const btn = event.target;
            if (section.classList.contains('hidden')) {
                section.classList.remove('hidden');
                btn.textContent = '🔒 隐藏访客订阅';
            } else {
                section.classList.add('hidden');
                btn.textContent = '🔓 查看访客订阅';
            }
        }

        ${hasKV ? `
        async function saveContent(button) {
            const textarea = document.getElementById('content');
            const status = document.getElementById('saveStatus');
            const originalText = button.textContent;
            
            try {
                button.disabled = true;
                button.textContent = '⏳ 保存中...';
                status.textContent = '';
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: textarea.value,
                    headers: {
                        'Content-Type': 'text/plain;charset=UTF-8',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (response.ok) {
                    const now = new Date().toLocaleString();
                    status.textContent = \`✅ 保存成功 \${now}\`;
                    status.style.color = '#28a745';
                } else {
                    const error = await response.text();
                    status.textContent = \`❌ 保存失败: \${error}\`;
                    status.style.color = '#dc3545';
                }
            } catch (error) {
                status.textContent = \`❌ 网络错误: \${error.message}\`;
                status.style.color = '#dc3545';
            } finally {
                button.disabled = false;
                button.textContent = originalText;
            }
        }

        // 自动保存
        let saveTimer;
        const textarea = document.getElementById('content');
        if (textarea) {
            textarea.addEventListener('input', () => {
                clearTimeout(saveTimer);
                saveTimer = setTimeout(() => {
                    const saveBtn = document.querySelector('.btn-primary');
                    if (saveBtn) saveContent(saveBtn);
                }, 3000);
            });
        }
        ` : ''}
    </script>
</body>
</html>`;
    }
}

// 主处理器
export default {
    async fetch(request, env, ctx) {
        // 基础安全检查
        if (!SecurityUtils.validateRequest(request)) {
            return new Response('Bad Request', { status: 400 });
        }

        const config = new Config(env);
        const cache = new CacheManager();
        const processor = new SubscriptionProcessor(config, cache);
        const converter = new FormatConverter(config);
        const storage = new StorageHandler(config);

        // 定期清理缓存
        ctx.waitUntil(cache.cleanup());

        try {
            const url = new URL(request.url);
            const userAgent = request.headers.get('User-Agent') || '';
            
            // 生成令牌
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timeTemp = Math.ceil(currentDate.getTime() / 1000);
            const fakeToken = await SecurityUtils.doubleMD5(`${config.token}${timeTemp}`);
            const guestToken = config.guestToken || await SecurityUtils.doubleMD5(config.token);

            // 验证访问权限
            const token = url.searchParams.get('token');
            const validTokens = [config.token, fakeToken, guestToken];
            const validPaths = [
                `/${config.token}`,
                `/${config.token}?`
            ];

            const hasValidToken = validTokens.includes(token);
            const hasValidPath = validPaths.some(path => 
                url.pathname === path || url.pathname.startsWith(path)
            );

            if (!hasValidToken && !hasValidPath) {
                // 未授权访问处理
                if (config.url302) {
                    return Response.redirect(config.url302, 302);
                }
                
                if (config.proxyUrl) {
                    return await this.handleProxy(config.proxyUrl, request);
                }

                return new Response(this.getDefaultHTML(), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=UTF-8' }
                });
            }

            // 已授权访问处理
            if (userAgent.toLowerCase().includes('mozilla') && !url.search) {
                // Web界面请求
                return await storage.handleKVRequest(request, env, guestToken);
            }

            // API请求处理
            return await this.handleAPIRequest(request, env, config, processor, converter, userAgent, fakeToken);

        } catch (error) {
            console.error('处理请求时发生错误:', error);
            return new Response('服务暂时不可用', { 
                status: 503,
                headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
        }
    },

    async handleAPIRequest(request, env, config, processor, converter, userAgent, fakeToken) {
        // 获取主要数据
        let mainData = [];
        if (env.KV) {
            const stored = await env.KV.get('LINK.txt');
            if (stored) {
                mainData = await processor.processData(stored);
            }
        } else {
            mainData = await processor.processData(config.mainData);
        }

        // 分离自建节点和订阅链接
        const selfNodes = [];
        const subscriptionUrls = [];
        
        mainData.forEach(line => {
            if (line.toLowerCase().startsWith('http')) {
                subscriptionUrls.push(line);
            } else {
                selfNodes.push(line);
            }
        });

        // 添加额外订阅链接
        if (config.linkSub) {
            const extraUrls = await processor.processData(config.linkSub);
            subscriptionUrls.push(...extraUrls.filter(url => ValidationUtils.isValidUrl(url)));
        }

        // 处理订阅
        const subscriptionResult = await processor.fetchSubscriptions(subscriptionUrls, request, userAgent);
        
        // 合并所有内容
        const allContent = [
            ...selfNodes,
            ...subscriptionResult.content
        ].filter(Boolean);

        // 去重
        const uniqueContent = [...new Set(allContent)];
        const finalContent = uniqueContent.join('\n');

        // 检测格式并转换
        const url = new URL(request.url);
        const format = converter.detectFormat(userAgent, url.searchParams);
        
        const subscriptionUrl = `${url.origin}/${fakeToken}?token=${fakeToken}${subscriptionResult.convertUrls}`;
        const result = await converter.convert(finalContent, format, subscriptionUrl);

        // 构建响应头
        const headers = {
            'Content-Type': 'text/plain; charset=utf-8',
            'Profile-Update-Interval': `${config.updateInterval}`,
            'Profile-web-page-url': request.url.split('?')[0],
            'Cache-Control': 'public, max-age=300',
            'X-Content-Type-Options': 'nosniff'
        };

        if (!userAgent.toLowerCase().includes('mozilla')) {
            headers['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(config.fileName)}`;
        }

        return new Response(result, { headers });
    },

    async handleProxy(proxyUrl, request) {
        try {
            const urls = proxyUrl.split('\n').filter(Boolean);
            const targetUrl = urls[Math.floor(Math.random() * urls.length)];
            
            const url = new URL(request.url);
            const proxyURL = new URL(targetUrl);
            
            const newUrl = `${proxyURL.protocol}//${proxyURL.hostname}${proxyURL.pathname}${url.pathname}${url.search}`;
            
            const response = await fetch(newUrl, {
                method: request.method,
                headers: request.headers,
                body: request.method === 'GET' ? null : request.body
            });

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers
            });
        } catch (error) {
            return new Response('代理请求失败', { status: 502 });
        }
    },

    getDefaultHTML() {
        return `<!DOCTYPE html>
<html>
<head>
    <title>CF Workers SUB</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); text-align: center; max-width: 500px; }
        .logo { font-size: 4em; margin-bottom: 20px; }
        h1 { color: #333; margin: 20px 0; }
        p { color: #666; line-height: 1.6; }
        .status { background: #e8f5e8; color: #2d5a2d; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🚀</div>
        <h1>CF Workers SUB</h1>
        <div class="status">
            <strong>✅ 服务运行正常</strong>
        </div>
        <p>这是一个订阅聚合服务。请使用正确的访问令牌来查看订阅内容。</p>
        <p><small>Powered by Cloudflare Workers</small></p>
    </div>
</body>
</html>`;
    }
};
