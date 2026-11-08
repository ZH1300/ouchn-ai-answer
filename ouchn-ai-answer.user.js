// ==UserScript==
// @name         国开 LMS AI 答案解析助手
// @namespace    https://lms.ouchn.cn/
// @version      4.4
// @description  获取国开 LMS 考试题目，调用 DeepSeek 生成答案并展示；支持单选/多选/判断/填空/简答/程序题；面板可拖动缩放；API Key 主密码加密存储，会话缓存二次加密；内存精简
// @author       https://github.com/ZH1300/
// @match        https://lms.ouchn.cn/exam/*
// @match        https://lms.ouchn.cn/api/exams/*
// @connect      lms.ouchn.cn
// @connect      api.deepseek.com
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_registerMenuCommand
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    // ==================== 配置 ====================
    const CONFIG = {
        DEEPSEEK_API_KEY: '',
        DEEPSEEK_URL: 'https://api.deepseek.com/v1/chat/completions',
        REQUEST_DELAY: 1500,
        MAX_RETRY: 2
    };

    const MIN_WIDTH = 320;
    const MIN_HEIGHT = 240;

    const ENC_KEY_STORE = 'deepseek_api_key_enc';
    const REMEMBER_STORE = 'deepseek_api_key_remember';
    const SESSION_STORE = 'ai_answer_key_session';
    const PRIVACY_ACK = 'privacy_ack_v1';
    const REMEMBER_DAYS = 7;

    // 状态
    let lastResults = [];          // 精简记录，不持有 q
    let isMaximized = false;
    let preMaximizeState = null;
    let isMinimized = false;
    let preMinHeight = null;
    let isRunning = false;
    let runToken = 0;
    let panelStateCache = null;

    // 复用型单例（避免高频 new）
    const htmlParser = new DOMParser();
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();

    // ==================== 题型映射 ====================
    const TYPE_MAP = {
        single_selection: '单选题',
        multiple_selection: '多选题',
        true_or_false: '判断题',
        fill_in_blank: '填空题',
        fill_blank: '填空题',
        short_answer: '简答题',
        essay: '论述题',
        text: '章节/说明'
    };
    const BLANK_TYPES = new Set(['fill_in_blank', 'fill_blank']);

    // ==================== 加密存储模块 ====================
    const CryptoStore = {
        bufToHex(buffer) {
            return Array.from(new Uint8Array(buffer))
                .map(b => b.toString(16).padStart(2, '0')).join('');
        },
        hexToBuf(hex) {
            return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        },
        async deriveKey(password, salt) {
            const keyMaterial = await crypto.subtle.importKey(
                'raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveKey']
            );
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        },
        async encrypt(plainText, password) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await this.deriveKey(password, salt);
            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, textEncoder.encode(plainText)
            );
            return JSON.stringify({
                v: 1,
                salt: this.bufToHex(salt),
                iv: this.bufToHex(iv),
                data: this.bufToHex(ciphertext)
            });
        },
        async decrypt(encryptedJson, password) {
            try {
                const obj = JSON.parse(encryptedJson);
                if (obj.v !== 1) throw new Error('Unsupported format');
                const salt = this.hexToBuf(obj.salt);
                const iv = this.hexToBuf(obj.iv);
                const data = this.hexToBuf(obj.data);
                const key = await this.deriveKey(password, salt);
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv }, key, data
                );
                return textDecoder.decode(decrypted);
            } catch (e) {
                return null;
            }
        },
        async encryptWithDeviceKey(plainText) {
            const key = await DeviceKey.get();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, textEncoder.encode(plainText)
            );
            return JSON.stringify({ v: 1, iv: this.bufToHex(iv), data: this.bufToHex(ct) });
        },
        async decryptWithDeviceKey(encryptedJson) {
            try {
                const obj = JSON.parse(encryptedJson);
                const key = await DeviceKey.get(false);
                if (!key) return null;
                const pt = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: this.hexToBuf(obj.iv) }, key, this.hexToBuf(obj.data)
                );
                return textDecoder.decode(pt);
            } catch (e) {
                return null;
            }
        }
    };

    // ==================== 设备密钥（IndexedDB，不可导出） ====================
    const DeviceKey = {
        _db: null,
        _open() {
            if (this._db) return Promise.resolve(this._db);
            return new Promise((resolve, reject) => {
                let req;
                try { req = indexedDB.open('ai-answer-helper', 1); }
                catch (e) { reject(e); return; }
                req.onupgradeneeded = () => {
                    const db = req.result;
                    if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys');
                };
                req.onsuccess = () => { this._db = req.result; resolve(this._db); };
                req.onerror = () => reject(req.error);
            });
        },
        async get(create = true) {
            const db = await this._open();
            const existing = await new Promise((resolve, reject) => {
                const tx = db.transaction('keys', 'readonly');
                const r = tx.objectStore('keys').get('device-key');
                r.onsuccess = () => resolve(r.result);
                r.onerror = () => reject(r.error);
            });
            if (existing) return existing;
            if (!create) return null;
            const key = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
            await new Promise((resolve, reject) => {
                const tx = db.transaction('keys', 'readwrite');
                tx.objectStore('keys').put(key, 'device-key');
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
            return key;
        },
        async clear() {
            try {
                const db = await this._open();
                await new Promise((resolve, reject) => {
                    const tx = db.transaction('keys', 'readwrite');
                    tx.objectStore('keys').delete('device-key');
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            } catch (e) {}
        }
    };

    // ==================== 解锁缓存（sessionStorage 二次加密） ====================
    async function setSessionKey(key) {
        try {
            const enc = await CryptoStore.encryptWithDeviceKey(key);
            sessionStorage.setItem(SESSION_STORE, JSON.stringify({
                enc,
                exp: Date.now() + 12 * 3600e3
            }));
        } catch (e) {}
    }
    async function getSessionKey() {
        try {
            const raw = sessionStorage.getItem(SESSION_STORE);
            if (!raw) return '';
            const obj = JSON.parse(raw);
            if (!obj.enc || (obj.exp && Date.now() > obj.exp)) {
                sessionStorage.removeItem(SESSION_STORE);
                return '';
            }
            return (await CryptoStore.decryptWithDeviceKey(obj.enc)) || '';
        } catch (e) {
            return '';
        }
    }
    function clearSessionKey() {
        try { sessionStorage.removeItem(SESSION_STORE); } catch (e) {}
    }

    async function loadRememberedKey() {
        const raw = GM_getValue(REMEMBER_STORE, '');
        if (!raw) return '';
        let obj;
        try { obj = JSON.parse(raw); } catch (e) {
            GM_deleteValue(REMEMBER_STORE);
            return '';
        }
        if (!obj || !obj.exp || Date.now() > obj.exp) {
            GM_deleteValue(REMEMBER_STORE);
            return '';
        }
        const key = await CryptoStore.decryptWithDeviceKey(obj.data);
        if (!key) {
            GM_deleteValue(REMEMBER_STORE);
            return '';
        }
        return key;
    }

    async function rememberKey(key, days = REMEMBER_DAYS) {
        try {
            const data = await CryptoStore.encryptWithDeviceKey(key);
            GM_setValue(REMEMBER_STORE, JSON.stringify({
                exp: Date.now() + days * 864e5,
                data
            }));
            return true;
        } catch (e) {
            console.warn('[AI答题] 无法记住 Key:', e);
            return false;
        }
    }

    function forgetRememberedKey() {
        GM_deleteValue(REMEMBER_STORE);
    }

    // ==================== 隐私确认 ====================
    function confirmPrivacy() {
        if (GM_getValue(PRIVACY_ACK, false)) return true;
        const msg = '【隐私提示】\n' +
            '本工具会把考试题干与选项发送到 DeepSeek（api.deepseek.com）以生成答案。\n\n' +
            '· 请确认这符合你所在机构的规定；\n' +
            '· 不要在含个人隐私或敏感信息的题目上使用；\n' +
            '· 生成结果仅供参考，提交前请自行核对。\n\n' +
            '是否继续？';
        if (confirm(msg)) {
            GM_setValue(PRIVACY_ACK, true);
            return true;
        }
        return false;
    }

    // ==================== API Key 管理 ====================
    async function unlockApiKey() {
        if (CONFIG.DEEPSEEK_API_KEY) return true;

        const cached = await getSessionKey();
        if (cached) {
            CONFIG.DEEPSEEK_API_KEY = cached;
            log('🔓 已复用本次会话解锁状态');
            return true;
        }

        const remembered = await loadRememberedKey();
        if (remembered) {
            CONFIG.DEEPSEEK_API_KEY = remembered;
            await setSessionKey(remembered);
            log('🔓 已自动解锁（记住期内）');
            return true;
        }

        const encrypted = GM_getValue(ENC_KEY_STORE, '');
        if (!encrypted) return false;

        const res = await showDialog({
            title: '🔑 解锁 API Key',
            message: '请输入主密码解密已保存的 DeepSeek API Key。',
            inputType: 'password',
            placeholder: '主密码',
            rememberLabel: `记住 ${REMEMBER_DAYS} 天（本机自动解锁，公共电脑勿勾选）`
        });
        if (!res || !res.value) return false;

        log('正在解密…');
        const key = await CryptoStore.decrypt(encrypted, res.value);
        if (!key) {
            alert('主密码错误或数据已损坏');
            return false;
        }
        CONFIG.DEEPSEEK_API_KEY = key;
        await setSessionKey(key);
        if (res.remember) {
            const ok = await rememberKey(key);
            if (!ok) alert('本浏览器不支持"记住"功能，仅本次会话内保持解锁。');
        }
        log('🔓 API Key 已解锁');
        return true;
    }

    async function saveApiKey() {
        const keyRes = await showDialog({
            title: '🔑 设置 DeepSeek API Key',
            message: '请粘贴你的 API Key（sk- 开头），将使用主密码加密后保存在本地。\n题目内容会发送到 DeepSeek 以生成答案。',
            inputType: 'text',
            placeholder: 'sk-...',
            defaultValue: CONFIG.DEEPSEEK_API_KEY || ''
        });
        if (!keyRes) return;
        const key = keyRes.value.trim();
        if (!key) { alert('API Key 不能为空'); return; }

        const pwdRes = await showDialog({
            title: '🔒 设置主密码',
            message: '主密码用于加密 API Key，请务必记住，忘记无法找回。',
            inputType: 'password',
            placeholder: '主密码（至少 6 位）',
            rememberLabel: `记住 ${REMEMBER_DAYS} 天（本机免输入解锁）`
        });
        if (!pwdRes) return;
        if (!pwdRes.value || pwdRes.value.length < 6) {
            alert('主密码至少 6 位');
            return;
        }

        log('正在加密保存…');
        const encrypted = await CryptoStore.encrypt(key, pwdRes.value);
        GM_setValue(ENC_KEY_STORE, encrypted);
        CONFIG.DEEPSEEK_API_KEY = key;
        await setSessionKey(key);

        if (pwdRes.remember) {
            const ok = await rememberKey(key);
            if (!ok) alert('本浏览器不支持"记住"功能，仅本次会话有效。');
        } else {
            forgetRememberedKey();
        }

        log('✅ API Key 已加密更新');
        alert(`API Key 已加密保存。${pwdRes.remember
            ? `${REMEMBER_DAYS} 天内本机自动解锁。`
            : '下次使用需输入主密码解锁。'}`);
    }

    async function clearApiKey() {
        if (!confirm('确定要清除本地保存的 API Key 吗？（含加密数据、记住状态、会话缓存）')) return;
        GM_deleteValue(ENC_KEY_STORE);
        forgetRememberedKey();
        clearSessionKey();
        CONFIG.DEEPSEEK_API_KEY = '';
        await DeviceKey.clear();
        log('🗑️ 已清除本地 API Key');
        alert('已清除本地全部 API Key 数据。');
    }

    function lockNow() {
        CONFIG.DEEPSEEK_API_KEY = '';
        clearSessionKey();
        log('🔒 已锁定');
        alert(GM_getValue(REMEMBER_STORE, '')
            ? `已锁定当前会话。仍存在"记住 ${REMEMBER_DAYS} 天"记录，如需彻底锁定请使用菜单"忘记自动解锁状态"。`
            : '已锁定，下次使用需重新输入主密码。');
    }

    function forgetRemembered() {
        forgetRememberedKey();
        CONFIG.DEEPSEEK_API_KEY = '';
        clearSessionKey();
        log('🧹 已忘记自动解锁状态');
        alert('已清除自动解锁记录，下次需输入主密码。');
    }

    async function ensureApiKey() {
        if (CONFIG.DEEPSEEK_API_KEY) return true;
        const hasEnc = !!GM_getValue(ENC_KEY_STORE, '');
        if (hasEnc) return await unlockApiKey();
        await saveApiKey();
        return !!CONFIG.DEEPSEEK_API_KEY;
    }

    // ==================== 基础工具 ====================
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    function escapeHtml(s) {
        return String(s ?? '').replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    function getStemPreview(content, maxLen = 50) {
        const full = String(content || '').replace(/\s+/g, ' ').trim();
        return { text: full.slice(0, maxLen), truncated: full.length > maxLen };
    }

    function showDialog({ title, message, inputType = 'password',
                          placeholder = '', defaultValue = '', rememberLabel = null }) {
        return new Promise(resolve => {
            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;display:flex;align-items:center;justify-content:center;';

            const box = document.createElement('div');
            box.style.cssText = 'background:#1e1e2e;color:#cdd6f4;border:1px solid #313244;border-radius:12px;padding:18px;width:340px;max-width:90vw;font:13px/1.6 system-ui,sans-serif;box-shadow:0 12px 32px rgba(0,0,0,.6);';

            const h = document.createElement('div');
            h.textContent = title;
            h.style.cssText = 'color:#cba6f7;font-weight:700;font-size:14px;margin-bottom:10px;';
            box.appendChild(h);

            if (message) {
                const m = document.createElement('div');
                m.textContent = message;
                m.style.cssText = 'color:#9399b2;font-size:12px;margin-bottom:12px;white-space:pre-wrap;';
                box.appendChild(m);
            }

            const input = document.createElement('input');
            input.type = inputType;
            input.placeholder = placeholder;
            input.value = defaultValue;
            input.style.cssText = 'width:100%;box-sizing:border-box;padding:8px 10px;border-radius:6px;border:1px solid #45475a;background:#11111b;color:#cdd6f4;font-size:13px;outline:none;';
            box.appendChild(input);

            let checkbox = null;
            if (rememberLabel) {
                const wrap = document.createElement('label');
                wrap.style.cssText = 'display:flex;align-items:center;gap:6px;margin-top:10px;color:#a6adc8;font-size:12px;cursor:pointer;';
                checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = true;
                checkbox.style.cssText = 'margin:0;cursor:pointer;';
                wrap.appendChild(checkbox);
                wrap.appendChild(document.createTextNode(rememberLabel));
                box.appendChild(wrap);
            }

            const btnRow = document.createElement('div');
            btnRow.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;margin-top:16px;';

            const mkBtn = (text, primary) => {
                const b = document.createElement('button');
                b.textContent = text;
                b.style.cssText = `padding:7px 16px;border-radius:6px;font-size:12px;cursor:pointer;
                    border:1px solid ${primary ? '#cba6f7' : '#45475a'};
                    background:${primary ? '#cba6f7' : 'transparent'};
                    color:${primary ? '#1e1e2e' : '#cdd6f4'};
                    font-weight:${primary ? 700 : 400};`;
                return b;
            };
            const okBtn = mkBtn('确定', true);
            const cancelBtn = mkBtn('取消', false);
            btnRow.appendChild(cancelBtn);
            btnRow.appendChild(okBtn);
            box.appendChild(btnRow);
            overlay.appendChild(box);
            document.body.appendChild(overlay);

            let done = false;
            const finish = (val) => {
                if (done) return;
                done = true;
                document.removeEventListener('keydown', onKey, true);
                overlay.remove();
                resolve(val);
            };
            const submit = () => finish({
                value: input.value,
                remember: checkbox ? checkbox.checked : false
            });
            function onKey(e) {
                if (e.key === 'Enter') { e.preventDefault(); submit(); }
                else if (e.key === 'Escape') { e.preventDefault(); finish(null); }
            }

            okBtn.onclick = submit;
            cancelBtn.onclick = () => finish(null);
            overlay.onmousedown = (e) => { if (e.target === overlay) finish(null); };
            document.addEventListener('keydown', onKey, true);
            setTimeout(() => { input.focus(); input.select(); }, 30);
        });
    }

    function gmRequest(options) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                timeout: 30000,
                ...options,
                onload: resolve,
                onerror: (err) => reject(new Error(
                    (err && (err.error || err.message)) || '网络请求失败'
                )),
                ontimeout: () => reject(new Error('请求超时'))
            });
        });
    }

    /**
     * 安全解析 JSON：整体解析失败时用括号配对（含字符串状态机）
     * 提取第一个完整对象，避免贪婪正则截取过多。
     */
    function safeJson(text) {
        if (!text) return null;
        try { return JSON.parse(text); } catch (_) {}
        const s = String(text);
        const start = s.indexOf('{');
        if (start === -1) return null;
        let depth = 0, inStr = false, esc = false;
        for (let i = start; i < s.length; i++) {
            const c = s[i];
            if (inStr) {
                if (esc) esc = false;
                else if (c === '\\') esc = true;
                else if (c === '"') inStr = false;
            } else {
                if (c === '"') inStr = true;
                else if (c === '{') depth++;
                else if (c === '}') {
                    depth--;
                    if (depth === 0) {
                        try { return JSON.parse(s.slice(start, i + 1)); }
                        catch (_) { return null; }
                    }
                }
            }
        }
        return null;
    }

    function stripHtml(html) {
        if (!html) return '';
        let s = String(html)
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<\/p>\s*<p[^>]*>/gi, '\n')
            .replace(/<\/p>/gi, '\n');
        try {
            const doc = htmlParser.parseFromString(s, 'text/html');
            s = doc.body.textContent || '';
        } catch (_) {
            s = s.replace(/<[^>]+>/g, '');
        }
        return s
            .replace(/\u00a0/g, ' ')
            .replace(/[ \t]+/g, ' ')
            .replace(/\n{3,}/g, '\n\n')
            .trim();
    }

    /** 填空题题干：把 __blank__ 替换为【空N】，再提取文本 */
    function prepareContent(html) {
        if (!html) return '';
        const s = String(html)
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<\/p>\s*<p[^>]*>/gi, '\n')
            .replace(/<\/p>/gi, '\n');
        let out;
        try {
            const doc = htmlParser.parseFromString(s, 'text/html');
            doc.querySelectorAll('.__blank__').forEach((el, idx) => {
                const num = (el.querySelector('.circle-number')?.textContent || '').trim()
                    || String(idx + 1);
                el.replaceWith(`【空${num}】`);
            });
            out = doc.body.textContent || '';
        } catch (_) {
            out = s.replace(/<[^>]+>/g, '');
        }
        return out
            .replace(/\u00a0/g, ' ')
            .replace(/[ \t]+/g, ' ')
            .replace(/\n{3,}/g, '\n\n')
            .trim();
    }

    function countBlanks(html) {
        if (!html) return 0;
        const m = String(html).match(/__blank__/g);
        return m ? m.length : 0;
    }

    function indexToLetter(i) { return String.fromCharCode(65 + i); }

    function log(msg) {
        console.log(`[AI答题] ${msg}`);
        const el = document.getElementById('ai-progress');
        if (el) { el.textContent = msg; el.title = msg; }
    }

    // ==================== 面板状态持久化 ====================
    function loadPanelState() {
        if (panelStateCache) return panelStateCache;
        const s = GM_getValue('panel_state', null);
        panelStateCache = (s && typeof s === 'object') ? s : null;
        return panelStateCache;
    }
    function savePanelState(panel) {
        const r = panel.getBoundingClientRect();
        let height = Math.round(r.height);
        if (isMinimized && preMinHeight) {
            const h = parseInt(preMinHeight, 10);
            if (Number.isFinite(h) && h > 0) height = h;
        }
        panelStateCache = {
            left: Math.round(r.left),
            top: Math.round(r.top),
            width: Math.round(r.width),
            height
        };
        GM_setValue('panel_state', panelStateCache);
    }

    // ==================== 题目获取 ====================
    function parseExamId() {
        const m = (location.pathname + location.hash).match(/\/exam\/(\d+)/);
        return m ? m[1] : null;
    }

    async function fetchQuestions(examId) {
        const candidates = [
            `https://lms.ouchn.cn/api/exams/${examId}/distribute`,
            `https://lms.ouchn.cn/api/exams/${examId}/paper`,
            `https://lms.ouchn.cn/api/exams/${examId}/questions`
        ];
        for (const url of candidates) {
            try {
                log(`尝试接口：${url}`);
                const res = await gmRequest({
                    method: 'GET', url,
                    headers: { 'Accept': 'application/json' }
                });
                if (res.status !== 200) continue;
                const json = safeJson(res.responseText);
                if (!json) continue;
                if (Array.isArray(json.subjects)) {
                    const list = normalizeSubjects(json.subjects);
                    if (list.length) {
                        log(`✅ 获取到 ${list.length} 道题目`);
                        return list;
                    }
                }
                const list = extractQuestions(json);
                if (list.length) {
                    log(`✅ 获取到 ${list.length} 道题目（兜底解析）`);
                    return list;
                }
            } catch (e) {
                console.warn('[AI答题] 请求失败:', url, e.message);
            }
        }
        return [];
    }

    /** 章节标题判定：type=text 且无选项且分值为 0 */
    function isSectionHeader(item) {
        if (!item || typeof item !== 'object') return false;
        if (item.type !== 'text') return false;
        const hasOptions = Array.isArray(item.options) && item.options.length > 0;
        const point = parseFloat(item.point || '0');
        return !hasOptions && point === 0;
    }

    function normalizeSubjects(subjects) {
        const result = [];
        for (const s of subjects) {
            if (!s || typeof s !== 'object') continue;
            if (isSectionHeader(s)) continue;
            const hasOptions = Array.isArray(s.options) && s.options.length > 0;
            if (!s.description && !hasOptions) continue;
            result.push(normalizeQuestion(s));
        }
        return result.sort((a, b) => (a.sort ?? 0) - (b.sort ?? 0));
    }

    /** 只保留渲染与格式化需要的字段；不保留 raw/id 等原始对象 */
    function normalizeQuestion(s) {
        const rawOptions = Array.isArray(s.options)
            ? [...s.options].sort((a, b) => (a.sort ?? 0) - (b.sort ?? 0))
            : [];
        const options = rawOptions.map((o, i) => ({
            key: indexToLetter(i),
            text: stripHtml(o.content || o.value || o.text || '')
        }));

        const type = s.type;
        const isBlank = BLANK_TYPES.has(type);
        const content = prepareContent(s.description || s.content || '');
        const blankCount = isBlank
            ? (countBlanks(s.description || s.content || '') || 1)
            : 0;

        return {
            type,
            typeLabel: TYPE_MAP[type] || type,
            content,
            options,
            blankCount,
            point: s.point,
            sort: s.sort,
            answered: !isBlank && (s.answer_number || 0) > 0
        };
    }

    function extractQuestions(json) {
        const found = [];
        const seen = new Set();
        function walk(node, depth) {
            if (!node || depth > 6 || typeof node !== 'object') return;
            if (Array.isArray(node)) {
                if (node.length && node.every(isQ)) {
                    node.forEach(q => {
                        if (!seen.has(q.id)) {
                            seen.add(q.id);
                            found.push(normalizeQuestion(q));
                        }
                    });
                    return;
                }
                node.forEach(item => walk(item, depth + 1));
                return;
            }
            for (const k of Object.keys(node)) walk(node[k], depth + 1);
        }
        function isQ(item) {
            if (!item || typeof item !== 'object') return false;
            if (isSectionHeader(item)) return false;
            return !!(item.description && (item.type || item.options));
        }
        walk(json, 0);
        return found;
    }

    // ==================== Prompt & AI ====================
    function buildPrompt(q) {
        let typeHint = '根据题目作答';
        let formatHint = '{"answer": "你的答案"}';

        switch (q.type) {
            case 'single_selection':
                typeHint = '单选题，answer 填一个选项字母，例如 "B"';
                formatHint = '{"answer": "B"}';
                break;
            case 'multiple_selection':
                typeHint = '多选题，answer 填全部正确选项字母连写，例如 "ACD"';
                formatHint = '{"answer": "ACD"}';
                break;
            case 'true_or_false':
                typeHint = '判断题，answer 必须严格填 "正确" 或 "错误" 这两个词之一，不要填字母';
                formatHint = '{"answer": "正确"}';
                break;
            case 'fill_in_blank':
            case 'fill_blank': {
                const n = q.blankCount || 1;
                typeHint = `填空题，题干中的【空1】…【空${n}】表示需要填写的空位。请按空位顺序给出每个空的答案，答案要简洁准确。`;
                formatHint = n > 1
                    ? `{"answer": ["第1空答案", "第2空答案", ..., "第${n}空答案"]}`
                    : '{"answer": ["答案"]}';
                break;
            }
            case 'short_answer':
                typeHint = '简答题/程序题。请仔细阅读题干：若要求"写出运行结果"，只给出最终输出（保留输出中的空格和换行，不要加解释）；若要求"编写程序"，给出完整可编译的 C 代码；若要求分析函数功能，用简洁中文描述。';
                formatHint = '{"answer": "答案文本或代码"}';
                break;
            case 'essay':
                typeHint = '论述题，answer 填写核心论点摘要';
                formatHint = '{"answer": "核心论点摘要"}';
                break;
            default:
                break;
        }

        const optionText = q.options.length
            ? q.options.map(o => `${o.key}. ${o.text}`).join('\n')
            : '';

        return `请独立解答以下题目，严格只输出 JSON，不要任何解释。
${typeHint}

题型：${q.typeLabel || q.type}${q.blankCount ? `（${q.blankCount}个空）` : ''}
题干：${q.content}
${optionText ? `选项：\n${optionText}\n` : ''}
输出格式：${formatHint}`;
    }

    /**
     * 循环重试（避免递归叠加 Promise 闭包）：
     * - 网络错误、解析失败、429、5xx 可重试
     * - 其他 4xx 立即抛错
     */
    async function askAI(prompt) {
        if (!CONFIG.DEEPSEEK_API_KEY) throw new Error('未解锁 DeepSeek API Key');
        let lastErr = new Error('未知错误');

        for (let attempt = 0; attempt <= CONFIG.MAX_RETRY; attempt++) {
            if (attempt > 0) {
                const delay = (lastErr && lastErr.status === 429)
                    ? Math.min(2000 * Math.pow(2, attempt - 1), 15000)
                    : 1000 * attempt;
                await sleep(delay);
            }

            let res;
            try {
                res = await gmRequest({
                    method: 'POST',
                    url: CONFIG.DEEPSEEK_URL,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${CONFIG.DEEPSEEK_API_KEY}`
                    },
                    data: JSON.stringify({
                        model: 'deepseek-chat',
                        messages: [
                            { role: 'system', content: '你是一个严谨的答题助手，只输出 JSON，不要任何解释。' },
                            { role: 'user', content: prompt }
                        ],
                        temperature: 0.1,
                        response_format: { type: 'json_object' }
                    })
                });
            } catch (e) {
                lastErr = new Error(`网络请求失败：${(e && e.message) || e}`);
                continue;
            }

            if (res.status === 200) {
                const json = safeJson(res.responseText);
                const raw = json?.choices?.[0]?.message?.content;
                const parsed = safeJson(raw);
                if (parsed && parsed.answer !== undefined) return parsed.answer;
                lastErr = new Error('AI 返回无法解析');
                continue;
            }

            const status = res.status;
            const err = new Error(`AI 接口 ${status}: ${String(res.responseText || '').slice(0, 120)}`);
            err.status = status;
            if (status === 429 || status >= 500) {
                lastErr = err;
                continue;
            }
            throw err;
        }
        throw lastErr;
    }

    // ==================== 答案格式化 ====================
    function normalizeFillAnswer(answer) {
        if (answer == null) return [];
        const coerce = (v) => {
            if (v == null) return '';
            if (typeof v === 'string') return v.trim();
            if (typeof v === 'number' || typeof v === 'boolean') return String(v);
            if (typeof v === 'object') {
                const t = v.text ?? v.value ?? v.content ?? v.answer;
                if (t != null) return String(t).trim();
                try { return JSON.stringify(v); } catch (_) { return ''; }
            }
            return String(v).trim();
        };

        if (Array.isArray(answer)) {
            return answer.map(coerce).filter(Boolean);
        }
        const s = String(answer).trim();
        if (s.startsWith('[')) {
            try {
                const arr = JSON.parse(s);
                if (Array.isArray(arr)) return arr.map(coerce).filter(Boolean);
            } catch (_) {}
        }
        const parts = s.split(/\n+|；|;|、/).map(x => x.trim()).filter(Boolean);
        return parts.length ? parts : [s];
    }

    function formatAnswerText(q, answer) {
        if (answer == null) return '（无答案）';

        if (BLANK_TYPES.has(q.type)) {
            const arr = normalizeFillAnswer(answer);
            if (!arr.length) return '（无答案）';
            if (arr.length === 1) return arr[0];
            return arr.map((a, i) => `空${i + 1}：${a}`).join('；');
        }

        const s = String(answer).trim();

        if (q.type === 'true_or_false') {
            if (/^(正确|对|是|true|t)$/i.test(s)) return '正确';
            if (/^(错误|错|否|false|f)$/i.test(s)) return '错误';
            if (/^[A-Za-z]$/.test(s) && q.options.length) {
                const opt = q.options.find(o => o.key === s.toUpperCase());
                if (opt) {
                    const t = opt.text.trim();
                    if (/^(正确|对|是|true|t)$/i.test(t)) return '正确';
                    if (/^(错误|错|否|false|f)$/i.test(t)) return '错误';
                    return `${s.toUpperCase()}. ${t}`;
                }
            }
            return s;
        }

        if (q.type === 'single_selection' || q.type === 'multiple_selection') {
            if (/^[A-Za-z]+$/.test(s)) {
                return s.toUpperCase().split('').map(k => {
                    const opt = q.options.find(o => o.key === k);
                    return opt ? `${k}. ${opt.text}` : `${k}（选项未匹配）`;
                }).join('；');
            }
        }
        return s;
    }

    function copyText(text) {
        return new Promise((resolve, reject) => {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(resolve).catch(fallback);
            } else fallback();
            function fallback() {
                try {
                    const ta = document.createElement('textarea');
                    ta.value = text;
                    ta.style.cssText = 'position:fixed;opacity:0;';
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    ta.remove();
                    resolve();
                } catch (e) { reject(e); }
            }
        });
    }

    function copyAllAnswers() {
        if (!lastResults.length) { alert('还没有答案可复制'); return; }
        const text = lastResults.map(r => {
            const ans = r.error ? `【获取失败：${r.error}】` : r.formatted;
            return `第${r.index}题（${r.typeLabel}${r.blankCount ? `·${r.blankCount}空` : ''}）${ans}\n  // ${r.stemPreview.text}${r.stemPreview.truncated ? '…' : ''}`;
        }).join('\n\n');
        copyText(text)
            .then(() => log('✅ 已复制全部答案'))
            .catch(() => alert('复制失败，请手动选择文本复制'));
    }

    // ==================== 卡片样式（一次性注入，卡片用 class） ====================
    function ensureStyles() {
        if (document.getElementById('ai-answer-style')) return;
        const style = document.createElement('style');
        style.id = 'ai-answer-style';
        style.textContent = `
            .ai-card { background:#181825; border-radius:8px; padding:10px; margin-bottom:8px; }
            .ai-card.ok { border-left:3px solid #cba6f7; }
            .ai-card.error { border-left:3px solid #f38ba8; }
            .ai-card-head { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; gap:8px; }
            .ai-card-title { color:#cba6f7; font-weight:700; }
            .ai-card-tags { display:flex; gap:4px; flex-shrink:0; }
            .ai-tag { font-size:10px; background:#313244; padding:1px 6px; border-radius:4px; }
            .ai-tag.type { color:#6c7086; }
            .ai-tag.blank { color:#89b4fa; }
            .ai-tag.point { color:#f9e2af; }
            .ai-tag.done { color:#a6e3a1; }
            .ai-stem { color:#cdd6f4; margin-bottom:6px; line-height:1.55; word-break:break-word; white-space:pre-wrap; }
            .ai-options { color:#9399b2; font-size:11px; line-height:1.7; margin-bottom:6px; }
            .ai-answer { padding:6px 8px; border-radius:6px; font-size:12px; font-weight:600; word-break:break-word; white-space:pre-wrap; }
            .ai-answer.ok { color:#a6e3a1; background:#1b2b1b; }
            .ai-answer.error { color:#f38ba8; background:#2d1b22; font-weight:400; }
            .ai-card button.copy { margin-top:6px; padding:3px 10px; font-size:11px; background:#313244; color:#cdd6f4; border:none; border-radius:4px; cursor:pointer; }
        `;
        document.head.appendChild(style);
    }

    // ==================== 卡片渲染（不持有 q） ====================
    function renderCard(index, q, error, formatted) {
        const container = document.getElementById('ai-answer-results');
        if (!container) return;
        ensureStyles();

        const card = document.createElement('div');
        card.className = 'ai-card ' + (error ? 'error' : 'ok');

        const pointNum = Number(q.point);
        const pointTag = Number.isFinite(pointNum) && pointNum > 0
            ? `<span class="ai-tag point">${pointNum}分</span>` : '';
        const blankTag = q.blankCount
            ? `<span class="ai-tag blank">${q.blankCount}空</span>` : '';
        const answeredTag = q.answered
            ? `<span class="ai-tag done">已作答</span>` : '';

        const head = document.createElement('div');
        head.className = 'ai-card-head';
        head.innerHTML = `
            <span class="ai-card-title">第 ${Number(index)} 题</span>
            <span class="ai-card-tags">
                <span class="ai-tag type">${escapeHtml(q.typeLabel)}</span>
                ${blankTag}${pointTag}${answeredTag}
            </span>`;
        card.appendChild(head);

        const stem = document.createElement('div');
        stem.className = 'ai-stem';
        stem.textContent = q.content || '（题干为空）';
        card.appendChild(stem);

        if (q.options.length) {
            const optWrap = document.createElement('div');
            optWrap.className = 'ai-options';
            q.options.forEach(o => {
                const line = document.createElement('div');
                line.textContent = `${o.key}. ${o.text}`;
                optWrap.appendChild(line);
            });
            card.appendChild(optWrap);
        }

        const ansEl = document.createElement('div');
        ansEl.className = 'ai-answer ' + (error ? 'error' : 'ok');
        ansEl.textContent = error
            ? `❌ 获取失败：${error}`
            : `✅ 答案：${formatted}`;
        card.appendChild(ansEl);

        if (!error) {
            const btn = document.createElement('button');
            btn.className = 'copy';
            btn.textContent = '复制本题';
            btn.dataset.copy = String(index - 1);
            card.appendChild(btn);
        }

        container.appendChild(card);
        container.scrollTop = container.scrollHeight;
    }

    /** 事件委托：复制按钮不创建闭包，也不持有 q */
    function onCardClick(e) {
        const btn = e.target.closest('button[data-copy]');
        if (!btn) return;
        const idx = Number(btn.dataset.copy);
        const item = lastResults[idx];
        if (!item || !item.formatted) return;
        copyText(item.formatted).then(() => {
            btn.textContent = '✅ 已复制';
            setTimeout(() => { if (btn.isConnected) btn.textContent = '复制本题'; }, 1500);
        });
    }

    // ==================== 任务控制 ====================
    function stopRunning() {
        runToken++;
        isRunning = false;
    }

    function setStartBtnState(running) {
        const btn = document.getElementById('ai-start');
        if (!btn) return;
        btn.disabled = running;
        btn.textContent = running ? '生成中…' : '开始获取答案';
        btn.style.opacity = running ? '0.6' : '1';
        btn.style.cursor = running ? 'not-allowed' : 'pointer';
    }

    // ==================== 主流程 ====================
    async function main() {
        if (isRunning) {
            alert('任务正在运行中，请稍候或等待完成。');
            return;
        }
        if (!document.getElementById('ai-answer-panel')) createPanel();
        if (!confirmPrivacy()) return;

        const hasKey = await ensureApiKey();
        if (!hasKey) {
            alert('未解锁 API Key，无法运行。');
            return;
        }

        const examId = parseExamId();
        if (!examId) {
            alert('无法从 URL 识别考试 ID，请确认在考试页面运行。');
            return;
        }

        isRunning = true;
        const myToken = ++runToken;
        lastResults = [];
        const resultsEl = document.getElementById('ai-answer-results');
        if (resultsEl) resultsEl.innerHTML = '';
        setStartBtnState(true);

        try {
            log('正在获取题目...');
            const questions = await fetchQuestions(examId);
            if (myToken !== runToken) return;
            if (!questions.length) {
                log('❌ 未获取到题目，请查看 F12 控制台');
                return;
            }

            const stats = {};
            questions.forEach(q => stats[q.typeLabel] = (stats[q.typeLabel] || 0) + 1);
            const statStr = Object.entries(stats).map(([k, v]) => `${k}${v}`).join('、');
            log(`共 ${questions.length} 题（${statStr}），开始分析...`);

            for (let i = 0; i < questions.length; i++) {
                if (myToken !== runToken) return;
                const q = questions[i];
                const { text: preview } = getStemPreview(q.content, 20);
                log(`进度 ${i + 1}/${questions.length}：${q.typeLabel} - ${preview}...`);

                let formatted = null;
                let errMsg = null;
                try {
                    const answer = await askAI(buildPrompt(q));
                    if (myToken !== runToken) return;
                    formatted = formatAnswerText(q, answer);
                } catch (e) {
                    if (myToken !== runToken) return;
                    errMsg = e.message;
                }
                if (myToken !== runToken) return;

                // 精简记录：不持有 q / options / answer
                lastResults.push({
                    index: i + 1,
                    typeLabel: q.typeLabel,
                    blankCount: q.blankCount,
                    stemPreview: getStemPreview(q.content, 50),
                    formatted,
                    error: errMsg
                });
                renderCard(i + 1, q, errMsg, formatted);

                if (i < questions.length - 1) await sleep(CONFIG.REQUEST_DELAY);
            }
            log(`✅ 完成，共 ${questions.length} 道题`);
        } finally {
            if (myToken === runToken) {
                isRunning = false;
                setStartBtnState(false);
            }
        }
    }

    // ==================== 拖动 / 缩放 / 最大化 / 最小化 ====================
    function setMinimized(panel, minimized) {
        if (minimized === isMinimized) return;
        const body = panel.querySelector('#ai-body');
        const resizer = panel.querySelector('#ai-resizer');
        const header = panel.querySelector('#ai-header');
        if (!body || !resizer || !header) return;

        if (minimized) {
            preMinHeight = panel.style.height
                || (panel.getBoundingClientRect().height + 'px');
            body.style.display = 'none';
            resizer.style.display = 'none';
            panel.style.height = (header.offsetHeight || 40) + 'px';
            isMinimized = true;
        } else {
            body.style.display = 'flex';
            resizer.style.display = isMaximized ? 'none' : 'flex';
            panel.style.height = preMinHeight || '540px';
            isMinimized = false;
        }
    }

    function setupDrag(panel) {
        const header = panel.querySelector('#ai-header');
        header.addEventListener('mousedown', (e) => {
            if (e.button !== 0) return;
            if (e.target.closest('button')) return;
            e.preventDefault();

            const rect = panel.getBoundingClientRect();
            const startX = e.clientX, startY = e.clientY;
            const startLeft = rect.left, startTop = rect.top;
            document.body.style.userSelect = 'none';
            let moved = false;

            function onMove(ev) {
                const dx = ev.clientX - startX;
                const dy = ev.clientY - startY;
                if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
                let nl = startLeft + dx;
                let nt = startTop + dy;
                nl = Math.max(0, Math.min(window.innerWidth - 120, nl));
                nt = Math.max(0, Math.min(window.innerHeight - 40, nt));
                panel.style.left = nl + 'px';
                panel.style.top = nt + 'px';
            }
            function onUp() {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
                document.body.style.userSelect = '';
                if (moved && !isMaximized) savePanelState(panel);
            }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });

        header.addEventListener('dblclick', (e) => {
            if (e.target.closest('button')) return;
            toggleMaximize(panel);
        });
    }

    function toggleMaximize(panel) {
        if (isMinimized) setMinimized(panel, false);
        const resizer = panel.querySelector('#ai-resizer');
        if (!isMaximized) {
            preMaximizeState = {
                left: panel.style.left,
                top: panel.style.top,
                width: panel.style.width,
                height: panel.style.height
            };
            panel.style.left = '8px';
            panel.style.top = '8px';
            panel.style.width = (window.innerWidth - 16) + 'px';
            panel.style.height = (window.innerHeight - 16) + 'px';
            resizer.style.display = 'none';
            isMaximized = true;
        } else {
            if (preMaximizeState) {
                panel.style.left = preMaximizeState.left;
                panel.style.top = preMaximizeState.top;
                panel.style.width = preMaximizeState.width;
                panel.style.height = preMaximizeState.height;
            }
            resizer.style.display = 'flex';
            isMaximized = false;
        }
    }

    function setupResize(panel) {
        const resizer = panel.querySelector('#ai-resizer');
        resizer.addEventListener('mousedown', (e) => {
            if (e.button !== 0) return;
            e.preventDefault();
            e.stopPropagation();

            const rect = panel.getBoundingClientRect();
            const startX = e.clientX, startY = e.clientY;
            const startW = rect.width, startH = rect.height;
            const maxW = window.innerWidth - rect.left;
            const maxH = window.innerHeight - rect.top;
            document.body.style.userSelect = 'none';

            function onMove(ev) {
                let w = startW + (ev.clientX - startX);
                let h = startH + (ev.clientY - startY);
                w = Math.max(MIN_WIDTH, Math.min(maxW, w));
                h = Math.max(MIN_HEIGHT, Math.min(maxH, h));
                panel.style.width = w + 'px';
                panel.style.height = h + 'px';
            }
            function onUp() {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
                document.body.style.userSelect = '';
                savePanelState(panel);
            }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    }

    window.addEventListener('resize', () => {
        const p = document.getElementById('ai-answer-panel');
        if (!p) return;
        if (isMaximized) {
            p.style.width = (window.innerWidth - 16) + 'px';
            p.style.height = (window.innerHeight - 16) + 'px';
            return;
        }
        if (isMinimized) return;
        const r = p.getBoundingClientRect();
        if (r.right > window.innerWidth) p.style.left = Math.max(0, window.innerWidth - r.width) + 'px';
        if (r.bottom > window.innerHeight) p.style.top = Math.max(0, window.innerHeight - r.height) + 'px';
    });

    // ==================== 创建面板 ====================
    function createPanel() {
        if (document.getElementById('ai-answer-panel')) return;

        isMaximized = false;
        preMaximizeState = null;
        isMinimized = false;
        preMinHeight = null;

        const saved = loadPanelState() || {};
        const width = saved.width || 420;
        const height = saved.height || 540;
        let left = saved.left;
        let top = saved.top;
        if (left == null || top == null) {
            left = Math.max(8, window.innerWidth - width - 16);
            top = Math.max(8, window.innerHeight - height - 16);
        }
        if (left + width > window.innerWidth) left = Math.max(8, window.innerWidth - width - 8);
        if (top + height > window.innerHeight) top = Math.max(8, window.innerHeight - height - 8);

        const panel = document.createElement('div');
        panel.id = 'ai-answer-panel';
        panel.style.cssText = `
            position: fixed; left: ${left}px; top: ${top}px;
            width: ${width}px; height: ${height}px;
            z-index: 99999; background: #1e1e2e; color: #cdd6f4;
            border-radius: 12px; font: 12px/1.5 system-ui, monospace;
            box-shadow: 0 8px 24px rgba(0,0,0,.5);
            display: flex; flex-direction: column;
            min-width: ${MIN_WIDTH}px; min-height: ${MIN_HEIGHT}px;
            overflow: hidden;
        `;
        panel.innerHTML = `
            <div id="ai-header" title="按住拖动移动面板 · 双击标题栏最大化/还原"
                 style="display:flex;justify-content:space-between;align-items:center;
                        padding:10px 12px;background:#181825;border-bottom:1px solid #313244;
                        cursor:move;user-select:none;flex-shrink:0;">
                <strong style="color:#cba6f7;font-size:13px;">📝 国开 AI 答案解析 v4.4</strong>
                <div style="display:flex;gap:4px;">
                    <button id="ai-minimize" title="最小化"
                            style="background:none;border:none;color:#6c7086;cursor:pointer;font-size:14px;padding:0 2px;">—</button>
                    <button id="ai-close" title="关闭"
                            style="background:none;border:none;color:#6c7086;cursor:pointer;font-size:14px;padding:0 2px;">✕</button>
                </div>
            </div>
            <div id="ai-body" style="display:flex;flex-direction:column;flex:1;min-height:0;padding:10px 12px;gap:8px;overflow:hidden;">
                <div style="display:flex;gap:6px;flex-shrink:0;">
                    <button id="ai-start"
                            style="flex:1;padding:7px;border:none;border-radius:6px;
                                   background:#cba6f7;color:#1e1e2e;font-weight:700;cursor:pointer;font-size:12px;">
                        开始获取答案
                    </button>
                    <button id="ai-setkey"
                            style="padding:7px 12px;border:1px solid #45475a;border-radius:6px;
                                   background:transparent;color:#cdd6f4;cursor:pointer;font-size:12px;">
                        API Key
                    </button>
                </div>
                <div id="ai-progress"
                     style="color:#9399b2;font-size:11px;min-height:16px;flex-shrink:0;
                            overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                    就绪，点击“开始获取答案”
                </div>
                <div id="ai-answer-results" style="flex:1;min-height:0;overflow-y:auto;padding-right:2px;"></div>
                <button id="ai-copy-all"
                        style="padding:6px;border:1px solid #45475a;border-radius:6px;flex-shrink:0;
                               background:transparent;color:#a6e3a1;cursor:pointer;font-size:12px;">
                    📋 复制全部答案
                </button>
            </div>
            <div id="ai-resizer" title="拖动调整大小"
                 style="position:absolute;right:0;bottom:0;width:20px;height:20px;
                        cursor:nwse-resize;z-index:10;display:flex;align-items:flex-end;
                        justify-content:flex-end;padding:2px;">
                <svg width="16" height="16" viewBox="0 0 16 16" style="opacity:.6;pointer-events:none;">
                    <path d="M14 6 L6 14 M14 10 L10 14" stroke="#6c7086" stroke-width="1.6" stroke-linecap="round"/>
                </svg>
            </div>
        `;
        document.body.appendChild(panel);

        ensureStyles();
        setupDrag(panel);
        setupResize(panel);

        // 事件委托：整个结果区一个监听
        panel.querySelector('#ai-answer-results').addEventListener('click', onCardClick);

        panel.querySelector('#ai-close').onclick = () => {
            stopRunning();
            panel.remove();
        };
        panel.querySelector('#ai-start').onclick = () => main();
        panel.querySelector('#ai-copy-all').onclick = () => copyAllAnswers();
        panel.querySelector('#ai-setkey').onclick = () => saveApiKey();
        panel.querySelector('#ai-minimize').onclick = () => setMinimized(panel, !isMinimized);
    }

    // ==================== 菜单 ====================
    GM_registerMenuCommand('📝 显示 AI 答案解析面板', createPanel);
    GM_registerMenuCommand('▶ 开始获取答案', main);
    GM_registerMenuCommand('🔑 设置 / 更新 API Key', saveApiKey);
    GM_registerMenuCommand('🔒 立即锁定（清除会话解锁）', lockNow);
    GM_registerMenuCommand('🧹 忘记自动解锁状态', forgetRemembered);
    GM_registerMenuCommand('🗑️ 清除本地加密 API Key', clearApiKey);

    setTimeout(createPanel, 1200);
})();
