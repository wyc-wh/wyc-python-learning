# 项目记忆·雷神之锤自动挖洞平台（索引）

> 详情 → `HANDBOOK.md`（十四 工程纪律 / 十四之二 补天SRC / 十四之三 漏洞盒子·联想LSRC / 十五 WebUI / 十六 复核按位置 / 十六之二 容器热更 / 十七 提交记录 / 十八 Kali）；过程 `2026-09-2x.md`；台账 `LEDGER.md`
> 回归：`PYTHONUTF8=1 <env python> _run_regress.py` → **套数/通过/失败/异常四项都核对**（只看「失败=0」会被「测试被删一半」骗过）。基线 **22 套 1041**

## 骨架
- 子命令：`init plan run autorun assets fuzz engage report verify status check lint submit coverage receipt`
- 清单默认 `auth.json`（`--auth-manifest` / env `PENTEST_AUTH`）；多项目 `auth.<项目>.json`
- ⭐ **作用域匹配只有一份 `scope_match.py`**：`example.com`=主域+子域；`.example.com`=后缀；CIDR；`=host` 仅该主机；`!host` 排除（最高）。曾各写一份→语义漂移（假绿灯）。新增 DSL 同步 `_test_scope_syntax_lab.py`
- 置信度 `detected🔍`→`confirmed✅`→`exploited💥`；**detected 不得提交**；`rate_findings` 会重置置信度→`generate_report` 必须回放 `session["verifications"]`
- **本机 shell 四坑**：git 用 PortableGit 全路径；**沙箱 bash 每条命令 PATH 被 shim 重置**；**PowerShell 抓不到 stdout**；**`curl -w %{size_download}` 不可信**（落文件 `wc -c`）

## ⭐ 复核必须按位置
- `rule_verifications[rule_id]={"records":{"站点|归一化路径":{…}}}`；**顶层刻意不写 level**→漏改消费方回落「疑似」（fail-closed）
- 唯一入口 `cvss.find_verification(...)`：**未登记直接 `None`（不退回规则级）**；**键必须带站点**
- 消费点全要跟：submit / report / SARIF / `evidence_lint` EL007
- 曾犯：按 `rule_id` 单条存→升级一处把未复核位置一起进稿

## 平台机制
- ⭐ **`_test_webui_lab.py` 用 `Handler.__new__` 直调 `api_*`，绕过 do_GET/main()**→「单测全绿」≠「能启动」；`_test_webui_startup_lab.py` 真 subprocess 兜底
- `submit` 模板随清单 `platform` 自适应（`_submit_platform_profile`）：含「补天」→6 项模板，否则厂商通用（`--vendor/--attribution/--weight`）
- 回环无认证是**刻意**的，不得破坏；合规闸 `sys.exit(2)` 会静默杀线程→`_capture()` 兜
- 容器热更一律 `deploy/sync_online.py`（bind/image **现查 `docker inspect`**，不可硬编码 + sha256 核对）

## 出口 / WAF
- ⭐ **境外扫描打中国目标会被地域封锁**→假阴性；`ssh -R 1080` 走本机出口
- ⭐ **大规模扫描会被 WAF 拉黑**→之后 matched=0 全是假阴性；**扫描中定期 curl 基线自检**；**WAF 拦截页返回 200**
- **目标也可能直接 TCP RST 路径探测**（联想 mail.lenovo.com）→目标行为非本机故障
- 报告 `_trust_section()`：出口非 ok 必须写「未取得有效证据」，**禁写「未发现问题」**

## 本地 Kali（VM）
- NAT `10.0.2.15`，宿主 `10.0.2.2`，转发 `127.0.0.1:2222→:22`；`kali`/`kali`；部署 `deploy/push_to_kali.py`，SSH 坏时 `VBoxManage guestcontrol`（`MSYS_NO_PATHCONV=1`）

## 判据
- ⭐ **D-01**：不得仅因信息有助侦察就给 `C:L`
- **EL021**：间隔 <6s 判 ERROR——**间隔是合规特性不是性能问题**（曾调 3s→证据全部作废）
- ⭐ **R014 分层**：`public:true` 只给**定义上非密钥**的标识；reCAPTCHA 的 site key 与 secret key **都是 40 位 `6L…`（不可区分）**→`ambiguous:true` + 按命中上下文降级，否则保守按凭据。整类打 public = 真泄 secret key 被静默吞掉

## 工程纪律（详版 HANDBOOK 十四）
- 基础八条（缺失≠`None`/多值头截断/改底层≠修调用点/urllib 跟随 30x/凭据只记类别长度/靶场自检 `status=None`/通配 DNS 先建基线/字典库逐条定性）→ **HANDBOOK 十四**
- ⭐ **「入口没被测」最贵**：绕过入口的测试→类型错误/同名方法覆盖长期漏检。新增入口必配「真跑起来」的端到端测试
- ⭐ **汇总运行器也是入口**：结果行四种风格，只写一种正则→全绿被报「异常」；双正则取最靠后 + 取不到判「异常」**绝不静默算过**
- ⭐ **「传了」≠「生效」**：跨主机/容器改文件必须 sha256 实证
- ⭐ **「通道不通」vs「参数被本地 shell 改写」**：MSYS 会改写参数成 `C:/.../usr/bin/x`；报错含本地路径前缀即判据；一律 `MSYS_NO_PATHCONV=1`
- ⭐ **改数据文件必须同时改生成它的脚本 + 往返证明**（`_build_p1_data.py` 整体覆盖 `secret_patterns.json`）
- ⭐ **一次性补丁先 DRY 再 WET**；必须幂等（**先查 `new` 是否已存在**，`count(old)==1` 不够）
- ⭐ **补丁里的三引号**：字符串**不能以 `"` 结尾**再接三引号→静默吞掉收尾引号、写坏 JSON（且因「new 已存在」永久跳过）
- ⭐ **长跑 runner 必须捕获 `TimeoutExpired`**：单台挂死不能拖垮整轮；超时记「未取得证据」，**不得当「无发现」**
- ⭐ **上下文判定窗口要小**：窗口一大，「隔半页的裸 key」会把前文 `grecaptcha(` 框进来，fail-closed 失效
- 子进程跨编码：子 `PYTHONIOENCODING=utf-8`，父 `encoding="utf-8", errors="replace"`
