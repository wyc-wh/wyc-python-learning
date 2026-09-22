# 项目记忆 - 自动挖洞平台

## 一、平台骨架

- `pentest-orchestrator/`：`orchestrator.py`(CLI) / `rules_engine.py` / `rules/` / `scanners.py`(nmap+nuclei) / `cvss.py` / `exploit.py`(人工确认制) / `manual_probe.py` / `webui.py`
- 子命令：`init plan autorun engage verify report status check lint submit`
- 合规闸：授权确认 + 范围校验 + `auth.json`(4 项校验) + append-only JSONL 审计 + 破坏性阶段默认禁用 + `allow_scanner=false` 硬开关
- 置信度三级：`detected 🔍` → `confirmed ✅` → `exploited 💥`。**`detected` 不得提交 SRC**
- **回放机制**：`rate_findings` 会重算并重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- CVSS：`compute_cvss31(av,ac,pr,ui,s,c,i,a)` 8 参 / `compute_cvss40(av,ac,at,pr,ui,vc,vi,va,sc,si,sa)` 11 参。**4.0 的 UI 只有 N/A/P，3.1 的 `UI:R` 对应 4.0 `UI:P`**，传 R 抛异常。一律用引擎算，别手算
- 工具：nmap 7.92 / nuclei v3.11.1(模板 13742，在 `tools/`) / ffuf / gobuster / feroxbuster / subfinder / amass / httpx / sqlmap / wafw00f。缺 nikto/whatweb/hydra/john（需 Perl/Ruby/gcc）

### 通用工程坑
- **nuclei 必须 `-no-interactsh`**：约 710 模板回连 oast.*，被网关判恶意流量直接 SIGTERM 掐断（零输出无提示）
- **去重两层**：解析层 `(template_id, matched_at)` + 评级层 `(类别, 归一化位置)`。nuclei 单模板可对同一 URL 吐 11 条；`type=generic` 视为未知类别，允许与内置类别同位置折叠
- `lines.append(*list)` 错 → `lines.extend(list)`
- **「工具没装」先怀疑调用侧**：中文 Windows 下 `encoding="utf-8"` 丢输出 → 多编码回退；`split()` 用在端口列表上会让 nmap 把端口串当主机名卡满超时。**耗时恰为超时整数倍 = 参数拼错；秒返空 = 编码问题**
- Go 系版本号先剥 ANSI 色码；`python -m <pkg>` 不万能（wafw00f 无 `__main__.py`）；`_find_exe` 要认 `.bat/.cmd/.py`

## 二、补天公益 SRC 规则（用户纠正，务必遵守）

- **公益SRC 不需核备案、不需事先报备**。官方"报备"条款只针对专属SRC/众测里影响业务连续性/用户数据安全的测试
- **公益SRC 无资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致；ICP 只在提交时作第 2 项「归属证明」
- 红线：禁自动化扫描器、禁高并发、禁破坏性、禁用户数据、禁范围外、禁未授权横向
- 目标侧自律：单线程、间隔 ≥6s、单次 ≤10 请求，全部写审计链
- **官方提交模板 6 项**（butian.net/Article/content/id/543）：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务。②③⑤ 需人工补；细则 `butian.net/Help/plan`
- 教训：**平台规则类流程建议，先查官方文档，别靠行业通例推断**

## 三、手工只读核查套路（命中率从高到低）

`python manual_probe.py --host <h> --session <id> --paths /,/robots.txt --check-http`
纪律写死在代码：仅 GET / 间隔 ≥6s / 单轮 ≤6 请求 / 证据 JSON + 审计链。

1. **⭐ 版本 → 厂商官方公告受影响范围（见 §四）**
2. **抓首页 href 的 host** 找业务系统 —— 比 crt.sh 更有效（crt.sh 226 条漏掉 6 个官网链出子域）
3. **客户端安全控制绕过**：见"正在验证您是否是真人"就读 JS。若只是 `document.cookie=...` + reload、服务端不校验 → 一条 curl 头绕过（CWE-602）
4. **后台入口常不在前台防护范围内**：`admin.php` 需单独查
5. **弱口令可行性判据**：搜 `seccode/验证码/captcha/AliyunCaptcha.js`。全 0 + 人机验证可绕过 = 具备条件；有验证码就别碰
6. **软 404 用 sha256 比对**：200 但与首页同 hash = catch-all，状态码会骗人
7. **明文 HTTP 分资产测**，管理入口单独看：有 HSTS ≠ 80 端口跳 HTTPS
8. **归属证明取首页页脚**：ICP号/主体/地址/版权一次拿全
9. **版本排除法**：拿到版本先查修复版本，别硬套 CVE

## 四、⭐「版本命中官方公告」打法

**困境**：SRC 不许爆破/利用，"无限爆破风险"怎么证明？
**解法**：拆成两条可只读取证的事实 —— ①版本落在厂商官方公告的受影响区间 ②站点未部署官方认可的缓解措施。两条成立即 confirmed，**不需要真爆破**。

实例（F-10，7.4/7.7）：`bbs.ikuai8.com` 页脚+meta generator 双处取证 `Discuz! X3.3` → Discuz! 官方公告【2021】第 1 号**明文点名「X3.3 全部 Release」**，官方定级高，X3.3 **已 EOL 无补丁** → 站点侧实测后台无验证码/人机验证可绕过/admin.php 不受保护/明文可达。

要点：查 CVE 更**要查厂商官方公告**（国内 CMS 以公告为准）；公告版本清单要逐条比对确认**被点名**；记下修复版本与 EOL 声明。公开研究可作"风险升级说明"，**标注未验证**。
定级：CWE-307 + CWE-1104，`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → 3.1 **7.4** / 4.0 **7.7**

## 五、可复用手法（jiaoyu.cn 实战）

- **安全头「占位符污染」**：头存在但值是 `value`/`off`/模板变量 → 浏览器忽略，防护失效。**比"缺失"更值得报**。取证前先排除自己脚本脱敏的可能
- **定级必须三合一**：HSTS 失效 + 明文 HTTP 可达 + 会话 Cookie 缺 Secure = 6.8；单独报"响应头问题"只有 3.1
- **零破坏探测写鉴权**：`DELETE /api/xxx/999999999`。返回"未登录"= 鉴权在路由前（安全）；返回"成功"/404 = 鉴权缺失
- **SPA 兜底假阳性**：`/.env` 200 但体积/hash 与首页一致 = catch-all
- **SPA 站归属取证**：页脚是 JS 渲染 → 去 `app.<hash>.js` 搜「版权所有/京ICP/有限公司」，一次拿全主体+地址+备案号；bundle 还能捞 API 清单与子域
- **「无测试账号」= 教育/政务类 SRC 硬阻塞**：未登录态天花板就是配置类问题，必须提前说明预期。严禁为拿账号用真实手机号注册、严禁测短信接口频控

## 六、只读规则引擎（2026-09-22 落地）

`rules/` + `rules_engine.py` + `orchestrator.py check`。靶场 `_test_rules_lab.py`。

- **不是扫描器**：不发 payload/不遍历/不并发/只 GET/HEAD → **不受 allow_scanner 闸约束**，但强制范围校验 + 限速(≥6s) + 请求预算 + 审计链
- **置信度恒为 detected 🔍**，绝不自动 confirmed；**排除必产 negative**（证明核查过）；预算耗尽标 `unfinished`
- 8 条规则：R001 安全头占位符 / R002 客户端绕过 / R003 明文+Cookie / R004 后台入口 / R005 版本命中官方公告 / R006 catch-all 基线(抑制器) / R007 零破坏写探测(默认关) / R008 敏感文件
- **关联分析比单条重要**：COR-T01(R001∧R003)=6.8；COR-A01(R004∧R005)=沿用公告向量 7.4。用 `supersedes` 避免重复提交
- 实战已自动复现人工发现：bbs.ikuai8.com → F-10(7.4)/F-05(6.5)；qmt.jiaoyu.cn → J-01(6.8)
- `check --auth-manifest` 支持多项目授权清单隔离

### 规则引擎实现要点
- **缓存 key 必须含请求头**：只按 (method,url) 会吞掉 R002「同 URL 带伪造 Cookie」的第二次请求（漏报不报错）
- **`OpenerDirector.open()` 不接受 `context=`**：只有 `urlopen` 接受；关 TLS 校验要 `build_opener(HTTPSHandler(context=ctx))`
- **`Powered by <a>X 3.3</a>` 正则里 `<...>` 必须整体可选** `(?:<[^>]*)?`
- **首页可能是拦截页**：版本信息在「绕过后的页面」→ R005 复用 R002 缓存再取（0 额外请求）
- **根路径跳 HTTPS ≠ 后台也跳**：R003 需对后台入口二段复检
- **靶场用协议嗅探单端口同时服务 HTTP/HTTPS**（首字节 0x16 = TLS ClientHello）

## 七、完整链路（P0，2026-09-22 打通）

`check → verify --rule → report → submit`（此前 check 是断头路，report 只读被闸禁的扫描器 findings → 报告只能手写）

- `session["rule_checks"][host]` = check 结果（裁掉原始请求体）
- `session["rule_verifications"][rule_id]` = 人工复核升级（report/submit 回放）
- `report` 新增「只读规则引擎核查结果」章节（发现表/证据复现/排除项/supersedes/覆盖度）
- `submit` 按补天 6 项模板出稿，**默认只输出 confirmed**，`--include-detected` 才出疑似
- `check --import-file` 零请求导入既有证据；report/verify/submit 均支持 `--session`

### 措辞铁律（会直接印进报告和提交稿）
- **规则名/发现名不写主观词**：R003 原名含「不跳转」→ 原样进报告。「返回完整内容」→ 改实测字节数 `{bytes}B`
  通则：**能被机器验证的写事实，不能验证的别写形容词**
- 提交稿「影响分析」别写套话 → 由 CVSS 向量推出「利用前提」(AV/AC/PR/UI/S) +「安全影响」(C/I/A)

## 八、证据完整性铁律（两次翻车换来）

### 8.1 「缺失」与「值为 None」必须字面可区分
`cookie_flags` 用 `None` 表缺失 → 下游把 JSON `null` 读成「SameSite=None」，据此写出「Chrome 80+ 会拒绝该 Cookie」——**自我削弱的附注**，等于替厂商备好驳回理由。
修复：缺失统一写字面量 `<未声明>` + `*_present` 布尔字段 + 单测锁死。
**通则：任何"属性不存在"的中间表示，都不能复用"属性有值"的值域。**

### 8.2 改了底层函数 ≠ 修好调用点
`fetch()` 加了 `follow_redirect`、handler 也写了，但 `main()` 里仍 `fetch(u)` 默认跟随 → CLI 证据依旧错。
**凡修取证类 bug，必须端到端复跑并比对原始输出。**

### 8.3 urllib 默认跟随 30x
会把「明文 HTTP 301」记成「200 不跳转」，曾使 3 条发现依据写错。
判断跳转必须 `HTTPRedirectHandler.redirect_request` 返回 None，再从 `HTTPError.headers` 取 Location。`manual_probe.py` 已有 `follow_redirect` 参数。

### 8.4 写前自问：这句措辞在帮我还是在帮厂商？
所有**降低本条危害性**的附注（"浏览器会拒绝"、"条件极其苛刻"、"实际影响有限"）都要确认是否基于被误读的数据。真实减分项**必须如实写**；误读出的减分项**必须删**。

## 九、测试基建铁律

1. **会写真实配置文件的测试，必须先备份再还原**（`_test_authgate.py` 曾删掉真实 auth.json）
2. **合规闸统一 rc=2 + 显式写 stderr**（`sys.exit("字符串")` 是 rc=1，测试会漏判）
3. **Windows 不能用 SO_REUSEADDR 探测端口** —— 允许重复绑定，探测永远成功
4. **测试必须环境隔离**：`PENTEST_AUTH` / `PENTEST_SESSIONS` + `tempfile.mkdtemp()`

## 十、环境

- git 不在 PATH：`C:/Users/wd/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`；`.gitignore` 排除 tools/、.sessions/、_lab/
- `git ls-files` 把非 ASCII 转成八进制 → 用 `-z` + escape_decode；中文名报 ENOSYS → `--ignore-errors`
- 沙箱 bash 缺 grep/tail/ls/dirname，用 python 替代；`dangerouslyDisableSandbox` 后 HTTPS 出网可用
- Windows nmap 无 Npcap 时 `-sV` 挂起 → 降级 `-sT`
- **图表导出**：`show_widget` 用 CSS 变量，脱离宿主不显示。出附件要单独写 SVG 写死颜色（浅色 #F1EFE8 底/#D3D1C7 边/#2C2C2A 字，危险 #FCEBEB/#A32D2D），转 PNG 用 Edge headless：
  `msedge.exe --headless=new --disable-gpu --no-sandbox --hide-scrollbars --force-device-scale-factor=2 --window-size=680,368 --screenshot=out.png in.svg`；校验尺寸用 `struct.unpack('>II', d[16:24])`（PIL 未装）

## 十一、PentAGI 评估结论（勿重复评估）

`D:\gihub\pentagi-main`（MIT，Go+Docker 12 服务）。**只借鉴方法论，不集成架构** —— Go/Python 不兼容、过度工程、其提示词「Never request permission」与人工确认制对撞、全攻击链自动化对 SRC 是合规风险。
已借鉴落地：置信度三级 / 覆盖度评估 / 脱敏规范 / CLI 反幻觉协议。

## 十二、已完成项目（勿重复开挖）

- **ikuai8.com**：F-10 高危（Discuz! X3.3 EOL + 登录失败计数失效，7.4/7.7）
- **jiaoyu.cn**：J-01 中危（qmt 安全头占位符失效，6.8/6.4）。**该站鉴权扎实，未挖到高危**；已登录态因无账号未覆盖

## 十三、证据自检 lint（P1，2026-09-22 落地）

`evidence_lint.py` + `orchestrator lint` 子命令。靶场 `_test_evidence_lint.py` 37/37。

**存在理由**：今天两次翻车的共同结构是**取证层取值正确、表述层结论错误**，
单元测试抓不到（它测函数返回值，不测「结论与证据是否自洽」）。

17 条断言，离线不发请求。最巧妙的三条：
- **EL004**：证据 sha256 与请求流水里**另一 URL** 相同 → 跟随跳转拿到落地页的特征
  （无需知道是否跟随，hash 撞车即暴露）
- **EL009**：自我削弱措辞（§8.3 的机器化），**引述语境豁免**
  （「拆开会被判影响不大」是强调合并，不是承认无害）
- **EL002**：`*_present=False` 却在文本里写成「属性=某值」

接入五处（缺一处门禁就是虚的）：`run_check` 出口 / `check --strict` /
`lint --file|--session` / `report` 小节 / **`submit` 门禁**（阻断项默认不出稿，
`--force` 才出稿并在稿内留痕）。

### lint 自身的两个坑（复用时避开）
- **结论文本与修复建议必须分开检查**：`remediation` 里的「应设为 SameSite=None」
  是建议值，计入会被当成「声称现状」→ 误报
- **合规闸统一 rc=2 + stderr**：`sys.exit("字符串")` 是 rc=1，门禁脚本会漏判
