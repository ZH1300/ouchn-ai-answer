// ==UserScript==
// @name         国开 LMS AI 答案解析助手
// @namespace    https://lms.ouchn.cn/
// @version      4.0
// @description  获取国开 LMS 考试题目，调用 DeepSeek 生成答案并展示；面板可拖动缩放；API Key 主密码加密存储
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
        DEEPSEEK_API_KEY: '',   // 运行时内存短暂持有，不持久化明文
        DEEPSEEK_URL: 'https://api.deepseek.com/v1/chat/completions',
        REQUEST_DELAY: 1500,
        MAX_RETRY: 2
    };

    const MIN_WIDTH = 320;
    const MIN_HEIGHT = 240;

    let lastResults = [];
    let isMaximized = false;
    let preMaximizeState = null;

    // ==================== 题型映射 ====================
    const TYPE_MAP = {
        single_selection: '单选题',
        multiple_selection: '多选题',
        true_or_false: '判断题',
        fill_blank: '填空题',
        short_answer: '简答题',
        essay: '论述题',
        text: '章节/说明'
    };

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
            const enc = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
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
            const enc = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await this.deriveKey(password, salt);
            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, enc.encode(plainText)
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
                return new TextDecoder().decode(decrypted);
            } catch (e) {
                return null;
            }
        }
    };

    // ==================== API Key 管理 ====================
    async function unlockApiKey() {
        const encrypted = GM_getValue('deepseek_api_key_enc', '');
        if (!encrypted) return false;

        const masterPwd = prompt('请输入主密码解锁 API Key：');
        if (!masterPwd) return false;

        const key = await CryptoStore.decrypt(encrypted, masterPwd);
        if (key) {
            CONFIG.DEEPSEEK_API_KEY = key;
            console.log('[AI答题] API Key 已解锁');
            return true;
        }
        alert('主密码错误或数据已损坏');
        return false;
    }

    async function saveApiKey() {
        const key = prompt('请输入 DeepSeek API Key：', CONFIG.DEEPSEEK_API_KEY || '');
        if (key === null) return;
        if (!key.trim()) { alert('API Key 不能为空'); return; }

        const masterPwd = prompt('请设置一个主密码（用于加密 Key，请务必记住，忘记无法找回）：');
        if (!masterPwd) { alert('未设置主密码，已取消保存。'); return; }
        if (masterPwd.length < 6) { alert('主密码建议至少 6 位。'); return; }

        const encrypted = await CryptoStore.encrypt(key.trim(), masterPwd);
        GM_setValue('deepseek_api_key_enc', encrypted);
        CONFIG.DEEPSEEK_API_KEY = key.trim();
        alert('API Key 已加密保存。下次使用时需输入主密码解锁。');
        log('✅ API Key 已加密更新');
    }

    function clearApiKey() {
        if (!confirm('确定要清除本地加密的 API Key 吗？')) return;
        GM_deleteValue('deepseek_api_key_enc');
        CONFIG.DEEPSEEK_API_KEY = '';
        log('🗑️ 已清除本地 API Key');
        alert('已清除本地加密的 API Key。');
    }

    /** 确保内存中有可用 Key，否则引导用户解锁或设置 */
    async function ensureApiKey() {
        if (CONFIG.DEEPSEEK_API_KEY) return true;
        const hasEnc = !!GM_getValue('deepseek_api_key_enc', '');
        if (hasEnc) {
            return await unlockApiKey();
        }
        // 首次使用
        await saveApiKey();
        return !!CONFIG.DEEPSEEK_API_KEY;
    }

    // ==================== 基础工具 ====================
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    function gmRequest(options) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                timeout: 30000,
                ...options,
                onload: resolve,
                onerror: (err) => reject(err),
                ontimeout: () => reject(new Error('请求超时'))
            });
        });
    }

    function safeJson(text) {
        if (!text) return null;
        try { return JSON.parse(text); } catch (_) {}
        const m = text.match(/\{[\s\S]*\}/);
        if (m) { try { return JSON.parse(m[0]); } catch (_) {} }
        return null;
    }

    function stripHtml(html) {
        if (!html) return '';
        let s = String(html)
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<\/p>\s*<p[^>]*>/gi, '\n')
            .replace(/<\/p>/gi, '\n');
        try {
            const doc = new DOMParser().parseFromString(s, 'text/html');
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

    function indexToLetter(i) { return String.fromCharCode(65 + i); }

    function log(msg) {
        console.log(`[AI答题] ${msg}`);
        const el = document.getElementById('ai-progress');
        if (el) { el.textContent = msg; el.title = msg; }
    }

    // ==================== 面板状态持久化 ====================
    function loadPanelState() {
        const s = GM_getValue('panel_state', null);
        return s && typeof s === 'object' ? s : null;
    }
    function savePanelState(panel) {
        const r = panel.getBoundingClientRect();
        GM_setValue('panel_state', {
            left: Math.round(r.left),
            top: Math.round(r.top),
            width: Math.round(r.width),
            height: Math.round(r.height)
        });
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

    function normalizeSubjects(subjects) {
        const result = [];
        for (const s of subjects) {
            if (!s || typeof s !== 'object') continue;
            const hasOptions = Array.isArray(s.options) && s.options.length > 0;
            const point = parseFloat(s.point || '0');
            if (s.type === 'text' && !hasOptions && point === 0) continue;
            if (!s.description && !hasOptions) continue;
            result.push(normalizeQuestion(s));
        }
        return result.sort((a, b) => (a.sort ?? 0) - (b.sort ?? 0));
    }

    function normalizeQuestion(s) {
        const rawOptions = Array.isArray(s.options)
            ? [...s.options].sort((a, b) => (a.sort ?? 0) - (b.sort ?? 0))
            : [];
        const options = rawOptions.map((o, i) => ({
            key: indexToLetter(i),
            text: stripHtml(o.content || o.value || o.text || ''),
            raw: o
        }));
        return {
            id: s.id,
            type: s.type,
            typeLabel: TYPE_MAP[s.type] || s.type,
            content: stripHtml(s.description || s.content || ''),
            options,
            point: s.point,
            sort: s.sort,
            answered: (s.answer_number || 0) > 0
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
            return !!(item.description && (item.type || item.options));
        }
        walk(json, 0);
        return found;
    }

    // ==================== Prompt & AI ====================
    function buildPrompt(q) {
        const typeHint = {
            single_selection: '单选题，answer 填一个选项字母，例如 "B"',
            multiple_selection: '多选题，answer 填全部正确选项字母连写，例如 "ACD"',
            true_or_false: '判断题，answer 必须严格填 "正确" 或 "错误" 这两个词之一，不要填字母',
            fill_blank: '填空题，answer 直接填写答案文本',
            short_answer: '简答题，answer 填写简明答案要点',
            essay: '论述题，answer 填写核心论点摘要'
        }[q.type] || '根据题目作答';

        const optionText = q.options.length
            ? q.options.map(o => `${o.key}. ${o.text}`).join('\n')
            : '（无选项）';

        return `请独立解答以下题目，严格只输出 JSON，不要任何解释。
${typeHint}

题型：${q.typeLabel || q.type}
题干：${q.content}
${q.options.length ? `选项：\n${optionText}` : ''}

输出格式：{"answer": "你的答案"}`;
    }

    async function askAI(prompt, retry = 0) {
        if (!CONFIG.DEEPSEEK_API_KEY) throw new Error('未解锁 DeepSeek API Key');
        try {
            const res = await gmRequest({
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
            if (res.status !== 200) throw new Error(`AI 接口 ${res.status}: ${res.responseText.slice(0, 120)}`);
            const json = safeJson(res.responseText);
            const raw = json?.choices?.[0]?.message?.content;
            const parsed = safeJson(raw);
            if (parsed && parsed.answer !== undefined) return parsed.answer;
            throw new Error('AI 返回无法解析');
        } catch (e) {
            if (retry < CONFIG.MAX_RETRY) {
                await sleep(1000 * (retry + 1));
                return askAI(prompt, retry + 1);
            }
            throw e;
        }
    }

    // ==================== 答案格式化 / 复制 ====================
    function formatAnswerText(q, answer) {
        if (answer == null) return '（无答案）';
        const s = String(answer).trim();
        if (q.type === 'true_or_false') {
            if (/^(正确|对|是|true|t|a)$/i.test(s)) return '正确';
            if (/^(错误|错|否|false|f|b)$/i.test(s)) return '错误';
            return s;
        }
        if (q.type === 'single_selection' || q.type === 'multiple_selection') {
            if (/^[A-Za-z]+$/.test(s)) {
                return s.toUpperCase().split('').map(k => {
                    const opt = q.options.find(o => o.key === k);
                    return opt ? `${k}. ${opt.text}` : k;
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
        const text = lastResults.map((r, i) => {
            const stem = (r.q.content || '').replace(/\s+/g, ' ').slice(0, 50);
            const ans = r.error ? `【获取失败：${r.error}】` : formatAnswerText(r.q, r.answer);
            return `第${i + 1}题（${r.q.typeLabel}）${ans}\n  // ${stem}${stem.length >= 50 ? '…' : ''}`;
        }).join('\n\n');
        copyText(text)
            .then(() => log('✅ 已复制全部答案'))
            .catch(() => alert('复制失败，请手动选择文本复制'));
    }

    // ==================== 答案卡片 ====================
    function renderCard(index, q, answer, error) {
        const container = document.getElementById('ai-answer-results');
        if (!container) return;

        const card = document.createElement('div');
        card.style.cssText = `background:#181825;border-radius:8px;padding:10px;margin-bottom:8px;
            border-left:3px solid ${error ? '#f38ba8' : '#cba6f7'};`;

        const head = document.createElement('div');
        head.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;gap:8px;';
        head.innerHTML = `
            <span style="color:#cba6f7;font-weight:700;">第 ${index} 题</span>
            <span style="display:flex;gap:4px;flex-shrink:0;">
                <span style="color:#6c7086;font-size:10px;background:#313244;padding:1px 6px;border-radius:4px;">${q.typeLabel}</span>
                ${q.point && q.point !== '0.0' ? `<span style="color:#f9e2af;font-size:10px;background:#313244;padding:1px 6px;border-radius:4px;">${q.point}分</span>` : ''}
                ${q.answered ? `<span style="color:#a6e3a1;font-size:10px;background:#313244;padding:1px 6px;border-radius:4px;">已作答</span>` : ''}
            </span>`;
        card.appendChild(head);

        const stem = document.createElement('div');
        stem.style.cssText = 'color:#cdd6f4;margin-bottom:6px;line-height:1.55;word-break:break-word;white-space:pre-wrap;';
        stem.textContent = q.content || '（题干为空）';
        card.appendChild(stem);

        if (q.options.length) {
            const optWrap = document.createElement('div');
            optWrap.style.cssText = 'color:#9399b2;font-size:11px;line-height:1.7;margin-bottom:6px;';
            q.options.forEach(o => {
                const line = document.createElement('div');
                line.textContent = `${o.key}. ${o.text}`;
                optWrap.appendChild(line);
            });
            card.appendChild(optWrap);
        }

        const ansEl = document.createElement('div');
        if (error) {
            ansEl.style.cssText = 'color:#f38ba8;background:#2d1b22;padding:6px 8px;border-radius:6px;font-size:12px;';
            ansEl.textContent = `❌ 获取失败：${error}`;
        } else {
            ansEl.style.cssText = 'color:#a6e3a1;background:#1b2b1b;padding:6px 8px;border-radius:6px;font-size:12px;font-weight:600;word-break:break-word;white-space:pre-wrap;';
            ansEl.textContent = `✅ 答案：${formatAnswerText(q, answer)}`;
        }
        card.appendChild(ansEl);

        if (!error) {
            const btn = document.createElement('button');
            btn.textContent = '复制本题';
            btn.style.cssText = 'margin-top:6px;padding:3px 10px;font-size:11px;background:#313244;color:#cdd6f4;border:none;border-radius:4px;cursor:pointer;';
            btn.onclick = () => {
                copyText(formatAnswerText(q, answer)).then(() => {
                    btn.textContent = '✅ 已复制';
                    setTimeout(() => btn.textContent = '复制本题', 1500);
                });
            };
            card.appendChild(btn);
        }

        container.appendChild(card);
        container.scrollTop = container.scrollHeight;
    }

    // ==================== 主流程 ====================
    async function main() {
        // 第一步：确保 API Key 可用（内存 → 解锁 → 首次设置）
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

        lastResults = [];
        const resultsEl = document.getElementById('ai-answer-results');
        if (resultsEl) resultsEl.innerHTML = '';
        setStartBtnState(true);

        try {
            log('正在获取题目...');
            const questions = await fetchQuestions(examId);
            if (!questions.length) {
                log('❌ 未获取到题目，请查看 F12 控制台');
                return;
            }

            const stats = {};
            questions.forEach(q => stats[q.typeLabel] = (stats[q.typeLabel] || 0) + 1);
            const statStr = Object.entries(stats).map(([k, v]) => `${k}${v}`).join('、');
            log(`共 ${questions.length} 题（${statStr}），开始分析...`);

            for (let i = 0; i < questions.length; i++) {
                const q = questions[i];
                log(`进度 ${i + 1}/${questions.length}：${q.typeLabel} - ${q.content.slice(0, 20)}...`);
                try {
                    const answer = await askAI(buildPrompt(q));
                    lastResults.push({ q, answer });
                    renderCard(i + 1, q, answer, null);
                } catch (e) {
                    lastResults.push({ q, answer: null, error: e.message });
                    renderCard(i + 1, q, null, e.message);
                }
                if (i < questions.length - 1) await sleep(CONFIG.REQUEST_DELAY);
            }
            log(`✅ 完成，共 ${questions.length} 道题`);
        } finally {
            setStartBtnState(false);
        }
    }

    function setStartBtnState(running) {
        const btn = document.getElementById('ai-start');
        if (!btn) return;
        btn.disabled = running;
        btn.textContent = running ? '生成中…' : '开始获取答案';
        btn.style.opacity = running ? '0.6' : '1';
        btn.style.cursor = running ? 'not-allowed' : 'pointer';
    }

    // ==================== 拖动 / 缩放 / 最大化 ====================
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
        const r = p.getBoundingClientRect();
        if (r.right > window.innerWidth) p.style.left = Math.max(0, window.innerWidth - r.width) + 'px';
        if (r.bottom > window.innerHeight) p.style.top = Math.max(0, window.innerHeight - r.height) + 'px';
    });

    // ==================== 创建面板 ====================
    function createPanel() {
        if (document.getElementById('ai-answer-panel')) return;

        isMaximized = false;
        preMaximizeState = null;

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
                <strong style="color:#cba6f7;font-size:13px;">📝 国开 AI 答案解析</strong>
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

        setupDrag(panel);
        setupResize(panel);

        panel.querySelector('#ai-close').onclick = () => panel.remove();
        panel.querySelector('#ai-start').onclick = () => main();
        panel.querySelector('#ai-copy-all').onclick = () => copyAllAnswers();
        panel.querySelector('#ai-setkey').onclick = () => saveApiKey();

        let minimized = false;
        let preMinHeight = null;
        panel.querySelector('#ai-minimize').onclick = () => {
            const body = panel.querySelector('#ai-body');
            const resizer = panel.querySelector('#ai-resizer');
            const header = panel.querySelector('#ai-header');
            if (!minimized) {
                preMinHeight = panel.style.height;
                body.style.display = 'none';
                resizer.style.display = 'none';
                panel.style.height = (header.offsetHeight || 40) + 'px';
                minimized = true;
            } else {
                body.style.display = 'flex';
                resizer.style.display = isMaximized ? 'none' : 'flex';
                panel.style.height = preMinHeight || (saved.height || 540) + 'px';
                minimized = false;
            }
        };
    }

    // ==================== 菜单 ====================
    GM_registerMenuCommand('📝 显示 AI 答案解析面板', createPanel);
    GM_registerMenuCommand('▶ 开始获取答案', main);
    GM_registerMenuCommand('🔑 设置 / 更新 API Key', saveApiKey);
    GM_registerMenuCommand('🗑️ 清除本地加密 API Key', clearApiKey);

    setTimeout(createPanel, 1200);
})();
