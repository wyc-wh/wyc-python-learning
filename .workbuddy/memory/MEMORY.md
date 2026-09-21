# 项目记忆 - 自动挖洞平台

## 知识库与技能

### CyberSecurity-Skills 技能库 (2026-09-21 接入)
- **来源**: https://github.com/Hi-FullHouse/CyberSecurity-Skills
- **本地路径**: C:\Users\wd\WorkBuddy\自动挖洞平台\CyberSecurity-Skills-master\
- **技能注册**: C:\Users\wd\.workbuddy\skills\cybersecurity-kb\SKILL.md
- **规模**: 39模块, 195技能
- **特点**: 覆盖渗透测试全流程，支持AI Agent集成 (CLI查询工具)

## 自动挖洞平台 - 核心交付

### pentest-orchestrator 编排器 (2026-09-21 搭建+扩展)
- **路径**: C:\Users\wd\WorkBuddy\自动挖洞平台\pentest-orchestrator\
- **模块**: orchestrator.py(主控 CLI) / scanners.py(只读扫描引擎，nmap/nuclei 集成+分层降级) / cvss.py(CVSS 3.1+4.0 双标准评级+置信度模型) / exploit.py(利用阶段·人工确认制) / webui.py(零依赖 Web 控制台) / download_tools.py + install_tools.py(工具安装)
- **形态**: 命令行编排器 + 零依赖 Web 控制台
- **子命令**: init(授权+范围校验+授权清单) / plan / autorun(recon·scan 真实只读探测) / engage(利用阶段人工确认) / **verify(人工复核升级置信度)** / run(dry-run) / report / status
- **合规闸**: 授权确认 + 范围校验 + **授权清单 auth.json（SRC 专用）** + 审计日志(append-only JSONL) + 破坏性阶段默认禁用 + autorun 仅限只读(recon/scan) + engage 人工确认制(不自动执行命令，破坏性阶段需 --destructive-confirm)
- **CVSS 引擎**: compute_cvss31(自检 4/4) + compute_cvss40(自检 3/3) + 置信度模型(自检 4/4)；rate_findings 消费 http_services + nmap_services(高危服务/版本泄露)→双向量评级+修复建议；不重复计 Web 端口
- **利用阶段**: exploit/privesc/postexploit/lateral/persistence 五阶段；playbook 从技能库 modules 03-07 拉真实技能；确认短语 CONFIRM-<PHASE>；只登记不执行
- **工具**: nmap 7.92 + nuclei v3.11.1 已装 tools/bin/（nmap 目录含 npcap-1.50.exe）；_which() 优先内置便携版，无需改系统 PATH；**nuclei 模板库 13742 个已装 tools/nuclei-templates/**（自动 -t 指定）
- **手册**: OPERATIONS.md v0.5（部署+开搞+排错+合规清单+置信度复核）
- **真实能力（已验证）**: nuclei 对真实靶场实跑命中（.env 泄露 7.5 / .git/config 5.4）；nmap -sV -sC 拿到产品+NSE（rdp-ntlm-info 泄露主机名/OS）
- **默认扫描范围**: `_DEFAULT_TPL_SUBDIRS`（misconfiguration/exposures/technologies/vulnerabilities/ssl/dns），单目标 85–110s；`--full-templates` 放开全库；`--allow-oob` 放开 OOB 模板

### 漏洞置信度三级模型（2026-09-21 落地，借鉴 PentAGI）
- **三级**：`detected` 🔍 疑似(扫描器命中，有误报) → `confirmed` ✅ 已确认(人工复核成立) → `exploited` 💥 已利用取证
- **铁律：`detected` 条目不可提交 SRC**（属低质量提交，影响账号信誉）
- **默认赋值规则**：nuclei 模板命中 = `detected`；banner/响应头/nmap 实测回显 = `confirmed`
- **`upgrade_confidence(rated, location, level, evidence)`**：**只升不降**；location 走 `_norm_location` 归一化
- **`verify` 命令**：只登记人工结论，**不自动验证**；升级为 confirmed/exploited **必须带 `--evidence`**
- **回放机制（关键坑）**：`rate_findings` 每次从原始扫描数据重算会重置置信度 →
  `generate_report` 必须**回放** `session["verifications"]` 逐条重放升级，否则 verify 结果丢失

### 关键设计决策（务必遵守）
- **nuclei 默认必须加 `-no-interactsh`**：整库约 710 个模板依赖 interactsh，未配 -iserver 会回连
  oast.pro/oast.online，被出口网关/沙箱判为「DNSLog平台」恶意流量并 **SIGTERM 掐断整条扫描**（零输出、无提示）。
  确需 OOB 时自建 interactsh + `--allow-oob` 显式开启
- **结果去重是硬需求**：nuclei 单模板常按 header/body 多次触发（实测同一 URL 吐 11 条）；路径指纹与 nuclei
  会对同一暴露重复上报。两层去重：解析层 `(template_id, matched_at)` + 评级层 `(类别, 归一化位置)`
- **位置归一化必须把 `/.env` 与 `http://host:port/.env` 折叠成同一 key**，且 nuclei 条目要从 `remediation` 回退抽 URL
- **nuclei 的 type=generic 视为「未知类别」**，允许与内置 info-leak/misconfig 同位置折叠，否则去重失效
- **路径指纹必须带 name/severity**（`COMMON_PATHS` 为 `path->(中文名,严重度)`），否则报告出空白项；
  `/`、`/robots.txt` 给 info，`/.env`、`/.git/HEAD` 给 high，避免正常首页被误报成漏洞
- **报告必须含「覆盖度与结论边界」章节**：显式列出未覆盖项（高端口/目录爆破/子域名/参数级/业务逻辑/
  口令/OOB），并声明「不得据本报告推断目标不存在其他漏洞」。缺此节读者会把「没扫到」误读成「没漏洞」
- **`lines.append(*list)` 是错的** → 必须 `lines.extend(list)`（静态编译查不出，只有 e2e 实跑暴露）
- **「工具没装」优先怀疑调用侧（2026-09-21 血的教训，两个 bug 叠加）**：
  ① **GBK 编码**：中文 Windows 下 `encoding="utf-8"` 会静默丢弃全部输出 → 已修 `_decode_out` 多编码回退
  ② **端口参数丢 `-p`**：`"...".split()` 用在固定端口列表上会让 nmap 把端口串当**目标主机名**，卡满超时。
     必须分支拼装 `["-p", "135,445"]`（固定列表）/ `["--top-ports", "100"]`（缺省）
  - **判别指纹：耗时恰好 = 超时值整数倍（241.0s = 120×2）→ 参数拼错**；秒返回空 → 编码问题
  - `_run_cmd` 已内建 `[WARN]`（>90% 超时）/ `[TIMEOUT] <完整命令>`；排错第一步先看这两行
  - **别轻易归因"沙箱限制"**：本次连续两次误判为沙箱，实际全是自身代码缺陷
- **`_sanitize_text` 的 `\xNN` 转义正则**必须 `\\x[0-9A-Fa-f]{2}(?:\\x[0-9A-Fa-f]{2})*`：
  每个转义自带 `\x` 前缀；用 `(?:\\xHH)+` 会把 `\x000`（=0x00+裸字符'0'）整体吃错
- **`run_scan` 用 `nuclei_ran`/`nuclei_ready` 区分「跑了没命中」vs「压根没跑」**，
  否则报告一律写"工具未安装"，误导排查方向

### 工具链盘点与补齐（2026-09-21）
- **三个脚本**：`env_audit.py`（盘点 22 项，分级 core/rec/opt）/
  `install_extra_tools.py`（GitHub API 查最新版 + 4 级镜像回退 + shim 生成）/
  `verify_tools.py`（**真实用例验证**，非版本号冒烟）
- **已装 18/22**：原 8 项 + 新装 ffuf/gobuster/feroxbuster/subfinder/amass/httpx/sqlmap/
  wafw00f/interactsh-client/git(shim)；报告 `TOOLCHAIN_REPORT.md`
- **未装 4 项**：nikto(需Perl)/whatweb(需Ruby)/hydra(C,需gcc)/john(C) —— 均 GitHub 0 assets 只发源码
- **「已装但没进 PATH」≠ 缺失**：git 2.55.0 一直在 PortableGit 的 **`cmd/`**（不是 `bin/`）下，
  之前误记「不可用」。先 glob 便携版目录，找到就只做 shim，别重新下载/别动 UAC 安装器
- **Go 系版本号必须先剥 ANSI 色码**：`[\x1b[34mINF\x1b[0m] Current Version: v2.16.0`
  用裸正则会取到颜色码里的 `34`；锚点用 `Current Version:`。各工具锚点不同
  （gobuster 无 `version` 子命令要用 `--help`；wafw00f 版本藏在 ASCII banner 后）
- **`python -m <pkg>` 不是万能的**：wafw00f 2.x 无 `__main__.py`，
  必须转发 pip 生成的 console script（`venv/Scripts/wafw00f.exe`）
- **非 exe 工具的 `_find_exe` 要支持 `.bat`/`.cmd`/`.py`**；bat 里 `%~dp0` 尾斜杠会吃掉引号，
  须写 `"%~dp0.\sqlmap.py"`
- **GitHub asset 命名不统一**：amd64 / Windows_x86_64 / x86_64-windows 三种都要认，
  排除 arm64/i386/debug；只认 amd64 会误判「无 Windows 包」
- **批量下载会被网关 SIGTERM** → 用 `--only xxx` 逐个装；GitHub releases 直连常 10053/502，走 ghfast
- **interactsh-client 默认连 oast.online 会被拦**（同 nuclei `-no-interactsh` 坑）→ 需自建 server
- **缺运行时的工具别硬装**：GitHub API `assets` 长度=0 即只发源码；需 UAC 的系统级安装
  （winget）只给命令交用户决定，不擅自执行

### PentAGI 评估结论（2026-09-21，勿重复评估）
- 路径 `D:\gihub\pentagi-main\pentagi-main`（MIT）；Go + Docker 12 服务 + Neo4j/Graphiti，10+ Agent
- **借鉴方法论，不集成架构**。四阻断：① Go vs Python 零依赖不兼容 ② 12+ 容器过度工程
  ③ 其提示词明令「Never request permission... Proceed immediately」，与本平台人工确认制**哲学对撞**
  ④ 全攻击链自动化（msf/impacket/mimikatz）对 SRC 是合规风险
- 如确需用：单独部署为**自建靶场**的独立工具，**绝不接 SRC 公益平台**
- 已借鉴落地：置信度三级模型（`verify`）/ 报告覆盖度评估 / 脱敏规范 / CLI 反幻觉协议
- 方法论文档：`~/.workbuddy/skills/cybersecurity-kb/references/AI-Agent渗透方法论-借鉴PentAGI.md`


### SRC 平台合规（补天等，重要）
- **红线**：补天《白帽子行为规范》明令禁止「高并发、测试自动化扫描器」+「大流量大规模扫描」+
  「范围外系统」+「未报备的影响业务测试」。**不可拿 autorun 直接扫补天公益 SRC**（轻则漏洞不收录/封号，
  重则触《网络安全法》第 27 条）
- **授权清单 auth.json**（模板 `auth.example.json`）：存在即启用严格校验，init 时校验 4 项，
  任一不过 `sys.exit(2)`：① 资产在 `in_scope` 内 ② `auth_id` 一致 ③ 在有效期内 ④ `allow_scanner=false` 则 autorun 被 BLOCK
- **限速档** `RATE_PROFILE`：conservative(默认,100端口/T2/30rps) / normal(1000端口/T3/100rps) /
  aggressive(全端口/T4/300rps，仅自有资产)；init 确定后存 session，autorun 自动应用
- **平台定位**：授权范围内的**辅助工具**，不是自动挖洞机。公益 SRC 只用 plan/report，探测手工做；
  专属 SRC 需书面许可扫描器才能用 autorun
- 无 auth.json 时向后兼容，退回 `--scope` 技术校验（自有资产/靶场场景）

## 环境约束
- git 在 bash 环境不可用 (PortableGit 路径问题)
- 中文 tar 必须用 python tarfile 解压（git bash tar 会导致 GBK 乱码，已踩坑修复）
- 使用 node.js https 模块下载 tar.gz 替代 git clone
- Python 3.13.12 可用于数据处理和验证
- sandbox 出站 TCP 连接被拦截（DNS 解析可通，但连外网端口失败）；端到端用本地 http.server 靶场验证，对外真实靶场需在本机/真实网络运行
- **沙箱 bash 缺 grep/tail/ls/dirname** 等命令（shim 环境），需用 python 替代；`dangerouslyDisableSandbox` 后 HTTPS 出网可用（github/nmap.org 可达）
- **下载坑**: nmap.org 直连慢易断→用 `curl -L -C -` 续传（7.93+ 无 win32 zip，用 7.92）；GitHub releases 国内 SSL 被重置→用镜像 ghfast.top/gh-proxy.com/ghproxy.net
- **Windows nmap 无 Npcap 时 -sV 挂起**：scanners 已加 _nmap_has_npcap() 预检→降级 -sT；装 tools/bin/nmap/npcap-1.50.exe 可解锁

## 公益 SRC（补天）实战打法（2026-09-21 首次完整跑通）

### 铁律
- **`allow_scanner=false` 是硬开关**：autorun/nmap/nuclei/ffuf/gobuster **一律不得对公益 SRC 目标运行**
- 目标侧交互上限参考：单次任务 **≤10 个请求、单线程、间隔 ≥6s**，且全部写审计链
- 被动情报（DNS DoH / crt.sh / 归档）优先，能不碰目标就不碰

### 三步判定攻击面（避免盲目测）
1. `sitemap.xml` 数动态入口（`.php`/`.asp`/`?`）—— 0 条即「全静态站」，
   弱口令/SQLi/上传类**直说攻击面不存在**，别硬凑
2. `robots.txt` 看是否为 CMS 默认模板残留 —— 残留≠真实路径，必须逐条验证
3. **软 404 用 sha256 比对**：`/administrator/` 返回 200 但与首页 hash 相同 = catch-all 回退，
   状态码会骗人，只看 200 会误报「后台泄露」

### 敏感发现的处理纪律
- crt.sh 常挖出 `jenkins.corp` / `harbor.internal` / `kiam` / `wiki` 等内网域
- 处理：**立刻写进 out_of_scope + 审计链留 SCOPE-GUARD 条目 + 报告单列「企业自查项」**
- **绝不作为 SRC 漏洞提交** —— 提交就等于承认做了未授权测试

### 报告必备章节
「覆盖度与结论边界」必须显式列出未覆盖项（目录爆破/参数注入/业务逻辑/鉴权/上传/组件CVE/
子域接管/OOB/高端口/内网域），并声明「未扫到 ≠ 不存在」。缺此节会被读成"没漏洞"

### 弱口令类需求
先确认有登录入口；无入口直接结论「攻击面不存在」。
有入口则：站内信报备 → 单账号×≤5 次常识口令 → 间隔 ≥10s → 禁字典/撞库/多线程 → 成功即停

### 平台侧小坑
- `cvss.compute_cvss31(av,ac,pr,ui,s,c,i,a)` 与 `compute_cvss40(av,ac,at,pr,ui,vc,vi,va,sc,si,sa)`
  **参数个数与取值不同**：4.0 的 UI 用 `N/A/P`（没有 `R`），且多 `at`
- 沙箱里 `head`/`tail`/`ls`/`dirname` 不可用，Python 输出别管道给它们

### 补天三类 SRC 的范围判定差异（2026-09-21 官方核实，别再搞混）
- **公益SRC**：**没有资产白名单**。官方定义「厂商注册后，白帽子随机发现漏洞提交，平台审核后通知企业认领」
  → 范围判据 = **资产归属能否证明**（ICP备案主体=厂商）+ 该项目历史已收录漏洞的域名分布 + 官网是否公开链出
- **专属SRC**：企业明确划定域名/IP/APP版本，白帽需审核准入 → 才有真正的 in_scope 列表
- **补天众测**：需排名前300等门槛，发VPN、限定时间窗，**企业仅授权VPN出口IP**，其余视为攻击

### 报备（官方原文口径）
「可能影响业务连续性、用户数据安全或系统稳定性的测试（核心功能篡改、批量数据操作等），
**必须提前向补天平台报备，经审核并与厂商确认后方可实施**」
→ 对象是**补天平台**（站内信 / 白帽咨询 010-56509093 / 官方群 1015536219），不是自行找厂商
→ 单次登录尝试不需报备；字典爆破/撞库必须报备且基本不批

### 公益SRC 官方提交模板 6 项（butian.net/Article/content/id/543）
① 漏洞URL ② **归属证明** ③ **首页截图(含地址栏)** ④ 漏洞证明 ⑤ **权重选择(爱站)** ⑥ 活动/任务
→ ②③⑤ 命令行做不了，必须人工浏览器补，缺项直接影响审核结果
→ 收录细则看 butian.net/Help/plan（判这类问题收不收，别靠猜）

### 通用教训
**涉及平台规则的流程性建议，先搜官方文档再给，别靠行业通例推断。**
（这次把"专属SRC有白名单"通例套到公益SRC上，给了用户错误指引）

## 测试基建铁律（2026-09-21 踩坑后确立）

1. **会写真实配置文件的测试，必须先备份再还原**，绝不能"用完就删"
   （`_test_authgate.py` 的 `os.remove(auth.json)` 删过真实补天清单）
2. **合规闸统一 rc=2 + 显式写 stderr**
   `sys.exit("字符串")` 是 rc=1 且走 stderr，与其它闸（rc=2/stdout）不一致，测试会漏判
3. **Windows 上不能用 SO_REUSEADDR 探测端口占用** —— 它允许重复绑定同一端口，
   探测"永远成功"，真实 server bind 才抛 WinError 10048。探测要复刻真实 bind 条件
4. **测试必须环境隔离**：`auth.json` 与 `.sessions/` 共用会导致
   (a) 靶场 e2e 被真实合规闸挡死 (b) 报告取到别的测试遗留的会话
   → 应支持 `PENTEST_AUTH` / `PENTEST_SESSIONS` 环境变量覆盖
5. **项目当前不是 git 仓库**（无 `.git`），git.exe 在
   `C:/Users/wd/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`（不在 PATH）
   → 改代码前记得先自己留副本，别指望 git 回滚

### 环境隔离约定（已落地，后续测试必须遵守）
- `orchestrator.py` 支持 **`PENTEST_AUTH`** / **`PENTEST_SESSIONS`** 环境变量覆盖
- 测试一律 `tempfile.mkdtemp()` + `env=` 传给 subprocess，**不碰真实 auth.json / .sessions**
- 测试末尾自检「真实文件 mtime 未变」

### 归属核实的高效入手点（2026-09-21 验证有效）
1. **首页页脚** = 归属证明金矿：ICP备案号 / 主体全称 / 地址 / 版权 / beian 链接一次拿全，
   正好对应补天提交模板第 2 项
2. **抓首页所有 href 的 host** = 找出官网公开链出的业务系统。
   实测比 crt.sh 更有效：crt.sh 完全没覆盖到 `demo/icc/yun/open/v.ikuai8.com` 这几个
3. 优先找 **`demo.*` 演示环境** —— 官方明示可访问，测它业务影响风险最低，
   是弱口令/默认口令测试的首选目标

### git 相关
- 仓库已建（2026-09-21），`.gitignore` 排除 tools/（数百MB）、.sessions/、_lab/
- git.exe 不在 PATH：`export PATH="/c/Users/wd/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd:$PATH"`
- `git ls-files` 把非 ASCII 路径转义成八进制，比对前要 `git ls-files -z` + escape_decode
- 个别中文名文件会报 `ENOSYS/Function not implemented`（环境怪癖），用 `--ignore-errors` 跳过

## 补天公益SRC 规则（2026-09-21 用户纠正，务必遵守）

- **公益SRC 不需要核备案，也不需要事先报备** —— 此前要求"逐个核 ICP 备案主体 + 站内信报备
  获批"是**过度解读**，已全面移除。依据：官方"报备"条款只针对「核心功能篡改、批量数据操作」
  等影响业务连续性/用户数据安全/系统稳定性的测试；该条与"授权前提"并列，约束的是**专属SRC/众测**。
  公益SRC =「随机发现 → 提交 → 平台审核 → 企业认领」，无事前审批入口。
- ICP 备案仅用于**提交时**官方模板第 2 项「归属证明」；开测前不用核。
- 范围判据 = **官网首页公开链出** + 版权/主体一致（不是项目页白名单，公益SRC 没有白名单）。
- 仍有效红线：禁自动化扫描器、禁高并发、禁破坏性、禁用户数据、禁范围外、禁未授权横向。

## 手工只读核查套路（manual_probe.py，可复用）

`pentest-orchestrator/manual_probe.py --host <h> --session <id> --paths /,/robots.txt --check-http`
纪律写死在代码里：仅 GET / 间隔 ≥6s / 单轮 ≤6 请求 / 证据 JSON + 审计链。

**高价值手法**：
1. **抓首页 href 找业务系统** —— 实测比 crt.sh 更有效（crt.sh 226 条完全漏掉 6 个官网链出子域）
2. **软404 判定**：`robots.txt` 返回 sha256 与首页相同 = catch-all，别被 200 骗
3. **客户端安全控制绕过**：看见"正在验证您是否是真人"就去看 JS —— 若 `document.cookie=...`
   + reload，服务端不校验 → **一个 curl 头就能绕过**（bbs.ikuai8.com 实测成立，中危）
4. **版本披露排除法**：拿到版本先查修复版本再决定是否报告（AList v3.63.0 > 3.57.0
   → 直接排除 CVE-2026-25161，别硬套 CVE）
5. **验证码存在性 = 弱口令可行性判据**：页面搜 seccode/验证码/captcha/AliyunCaptcha.js，
   全 0 才说明可爆破；有验证码就别碰（icc 有阿里云验证码 → 判定不可行）
