# 项目记忆 - 自动挖洞平台（速查）

> **详情层 `HANDBOOK.md`**：手法/规则引擎/lint/指纹/覆盖度/登录态/闭环/观测层/判据库/工程纪律/**补天SRC 十四之二**/**WebUI 十五~十五之三**；过程 `2026-09-2x.md`，待办 `LEDGER.md`。

## 骨架
- 工程结构 / 子命令 / 合规闸 / CVSS / 工具清单 → **HANDBOOK 十四·骨架清单**
- 置信度 `detected🔍`→`confirmed✅`→`exploited💥`；**detected 不得提交 SRC**。`rate_findings` 重算会重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- **本机 shell 四坑**：① git 用 PortableGit 全路径（`~/.workbuddy/binaries/PortableGit/versions/*/cmd/git.exe`）② **沙箱 bash 的 PATH 每条命令被 shim 重置** → 命令自带 `export PATH="/usr/bin:/bin:/mingw64/bin:/c/Windows/System32:$PATH"` ③ **PowerShell 抓不到 stdout**，删文件走 Python `os.remove` ④ **`curl -w %{size_download}` 不可信** → 落文件再 `wc -c` + 查 `</html>`
- **同文件多处 Edit 不要批量发**：实测单条消息里多个 `Edit` 调用只有第一条稳定落地，其余可能没生效或造成开闭标签错配；**改为一次性 Python 替换脚本（每条 `count==1` 断言）**

## Web 控制台 / UI（HANDBOOK 十五~十五之三）
- 合规闸 `sys.exit(2)` **静默杀死请求线程**（`SystemExit` 非 `Exception`，`socketserver` 不捕）→ 必须 `_capture()` 兜，再从日志挑 `[BLOCK]/[FAIL]`
- **Windows ADS**：`rules_x:port.json` 的 `:` 被 NTFS 当数据流 → 本体 0 字节但 `isfile()`/`getsize()` 全正常 → 一律 `safe_evidence_name()`
- **内嵌 PAGE 必须 raw string + 脚本切片拼接**（否则 JS 的 `\n` 编译期被解成真换行）；**前端也要门禁**：`node --check` 只取 `<script>` 标签之间的 JS，并断言 `$('#id')` 与内联 onclick 函数名一致
- **视觉验证**：无头 Chrome + **iframe 高度 ≤3500px**（超限不绘制 → **多张截图字节数相同 = 全没渲染**）；浅色主题另起 `<body class="light">` 实例
- **进度 / 门禁 / 危险度是三个独立维度**（`state` 走到哪 / `gate`+`need` 能不能进 / `hot` 危险度）：写成 `locked` → 「没做过」与「做了被锁」分不清
- **前端三个静默坑**：① 后端字段缺失 → `undefined||0` 印出「假事实」（「排除项 0 条」且无报错）② 内联 onclick 不能传 `JSON.stringify`（双引号提前闭合属性）→ 只传 key ③ 状态变了标签没同步（主题存了 localStorage 但按钮文案只在 toggle 里改）
- 驾驶舱数据后端驱动：风险四档**只计发现项**；严重度**归一**；越界数**只认审计链 BLOCK/REJECT**；**前端格式校验复用后端 `orch.validate_scope`**（假绿灯比不校验更危险）

## 证据与工程纪律（HANDBOOK 十四 · 20+ 条，只留最易再犯）
1. **「缺失」与「值为 None」字面可区分**：缺失写 `<未声明>` + `*_present`。**属性不存在的中间表示不能复用「有值」的值域**（曾把缺失读成 `SameSite=None`，等于替厂商备好驳回理由）
2. **改了底层函数 ≠ 修好调用点** → 端到端复跑并比对原始输出
3. **异常响应先取证再下结论**：直觉两次被推翻（疑似调试页 = WAF 拦截页 / 疑似泄露 = 站点自身 404 页）；**urllib 默认跟随 30x**，会把「明文 301」记成「200 不跳转」
4. **多值头会被 `dict(headers)` 截断，且 CSRF token ≠ 会话 Cookie** → Set-Cookie 单存 `_all_set_cookies`，两个正则必须互斥，否则「会话劫持链」被一句话驳回
5. **能被机器验证的写事实，不能验证的别写形容词**；**写前自问：这句措辞在帮我还是在帮厂商？**
6. **隐私铁律**：凭据只记类别/次数/长度，**不记值也不记哈希**；API 响应只记字段名/条数/sha256
7. **靶场必须自检 `status=None`**（忘 `verify_tls=False` → 假通过）；红时先分辨「数据脏」还是「代码错」
8. **禁 bash / `python -c` 内联写含反引号的中文长文本**（踩过两次）→ 用 Write 写 `.py`；**字典库原料「不读就信」风险最高** → 构建脚本强制逐条定性

## 判据与状态语义（HANDBOOK 十一~十三）
- **「排除项」是五种状态**（`no_issue_found`/`ruled_out`/`not_applicable`/`needs_follow_up`/`reported`），压成一个「排除」= 把「没拿到证据」读成「查过了没问题」
- **只读下升 `ruled_out` 的唯一合法路径 = 横向事实**（多条不同路径返回字节全同 + sha256 可核对）；边界：只排除「这个 200 是文件内容」，不解除「文件是否存在」
- **「规则执行了」≠「检查面被覆盖」**：覆盖度分子 = 「取得证据没有」，不是「跑过没有」
- **⭐ D-01**：**不得仅因信息有助于侦察就给 `C:L`** —— 版本 / source map / 路径只是暗示另一漏洞时，要么验完整链，要么 `C:N` 且不提交
- **R005 攻击面证据门槛**：厂商带 `_trigger_condition`（默认不触发）时**版本命中不足**；`ORDER` 里 **R004 必须早于 R005**
- **lint 第二道闸** EL030~EL036（EL035/EL036 警告级**不阻断提交**）；**补天 SRC 平台规则**（不需核备案 / 无白名单 / 提交 6 项）→ **HANDBOOK 十四之二**

## 台账
→ **已拆到 `LEDGER.md`**。ikuai8 = F-10 高危（7.4/7.7）；jiaoyu = J-01 中危，匿名侧扎实、登录态未覆盖；**回归基线 12 靶场 681 条全绿**。
