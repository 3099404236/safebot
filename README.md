# QQ 群聊安全扫描 Bot（UIAutomation 方案）

这是一个本地 Windows Python 程序，通过 UIAutomation 读取已打开的 QQ 群聊窗口，可见消息中发现 URL 后执行安全评分，并在风险高于安全阈值时通过 UIAutomation 回写群提示。程序不注入 QQ 进程。

## 设计思路

项目的核心选择是“零注入”：不加载 DLL、不 Hook QQ、不接管网络协议，也不依赖修改版客户端。程序作为独立进程运行，只通过 Windows 辅助功能接口读取 QQ 窗口已经渲染出来的可见内容，再通过 UIAutomation 定位输入框和发送按钮完成回复。

QQ NT 版基于 Chromium/Electron，聊天内容在渲染层中。Chromium 为了性能，默认不会一直生成完整无障碍树；当 Windows 讲述人、NVDA、JAWS 等辅助技术运行时，它会自动开启 accessibility tree。这个项目利用的是系统级辅助功能通道：先启动 Narrator，再启动 QQ，随后 Python 进程用 UIAutomation 读取无障碍树。这样既避开注入带来的封号和稳定性风险，也保留了足够的消息可见性。

从安全边界看，Bot 只处理“屏幕上已经可见”的消息和控件，相当于一个自动化屏幕阅读器加输入助手。代价是它受 QQ 窗口状态、当前可见区域和控件树结构影响；收益是实现路径干净，QQ 更新时只需要重新导出无障碍树并调整 selector。

## 当前实现

- QQ 窗口发现、UIAutomation 树导出、按配置 selector 定位消息列表/输入框/发送按钮
- 运行中动态发现 QQ 聊天窗口，排除标题为 `QQ` 的主窗口，新打开的群聊窗口会自动加入监控
- 可见消息轮询读取、内存去重、URL 提取
- VirusTotal v3 URL/文件报告查询，可选提交 URL/上传文件
- Google Safe Browsing v4 查询
- 自定义 URL 规则：新注册域名、HTTPS/证书、仿冒登录表单、隐藏 iframe、可疑 JS、meta refresh
- 本地文件规则：后缀/MIME 伪装、Office 宏、PDF JavaScript/OpenAction、ZIP 内可执行文件
- 文件消息下载流程：识别可见文件名，点击消息内下载按钮，监控 `qq_download_dir` 后扫描
- 白名单指令：`#信任 xxx.com`、`#取消信任 xxx.com`、`#白名单列表`
- CLI：`list-windows`、`dump-tree`、`scan-url`、`scan-file`、`run`

文件消息下载依赖 QQ 实际控件树和下载目录。拿到树结构后，需要确认 `download_button` selector 能在单条文件消息内部找到按钮，并在 `settings.json` 里填写 `qq_download_dir`。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

复制配置：

```powershell
Copy-Item config\settings.example.json config\settings.json
Copy-Item config\accessibility_map.example.json config\accessibility_map.json
Copy-Item config\whitelist.example.json config\whitelist.json
```

仓库只提交 `*.example.json` 模板。本机文件 `.env`、`config/settings.json`、`config/accessibility_map.json`、`config/whitelist.json` 已写入 `.gitignore`，不要手动上传到 GitHub；其中可能包含 API key、本机 QQ 控件路径或私有白名单。

API key 可以写进 `config/settings.json`，也可以放进环境变量：

```powershell
$env:VIRUSTOTAL_API_KEY="..."
$env:GOOGLE_SAFE_BROWSING_API_KEY="..."
```

## 第一阶段：导出 QQ 无障碍树

Chromium/Electron 只有在检测到辅助技术或显式启动参数时，才会生成完整无障碍树。推荐流程：

1. 先启动 Windows 讲述人：`Win + Ctrl + Enter`
2. 如有声音干扰，把讲述人或系统音量静音即可，进程保持运行
3. 再启动 QQ，并打开要监控的群聊独立窗口
4. 导出 UIAutomation 树

也可以用启动参数打开 QQ：

```powershell
Start-Process "C:\Path\To\QQ.exe" -ArgumentList "--force-renderer-accessibility"
```

把 `C:\Path\To\QQ.exe` 替换成你本机 QQ 的实际路径。

准备好群聊窗口后运行：

```powershell
python -m safebot list-windows --config config/settings.json
python -m safebot dump-tree --config config/settings.json --title "群名关键字" --depth 8 --output qq-tree.txt
```

用 `qq-tree.txt` 对照 Accessibility Insights，填写 `config/accessibility_map.json` 中的：

- `message_list`：消息列表控件路径
- `input_box`：消息输入框 selector
- `send_button`：发送按钮 selector（如果 `send_mode` 用 `button`）
- `download_button`：文件消息下载按钮 selector

不要猜路径。QQ 更新后如果读取失败，重新导出树并调整 selector。

## 单项扫描调试

```powershell
python -m safebot scan-url "https://example.com" --config config/settings.json
python -m safebot scan-file ".\sample.zip" --config config/settings.json
```

默认 `submit_urls_to_virustotal=false`、`upload_files_to_virustotal=false`，只查询已有报告，避免误上传隐私文件或消耗配额。确认策略后再打开提交开关。

文件消息自动下载还需要设置：

```json
{
  "bot": {
    "qq_download_dir": "C:/Users/你的用户名/Documents/Tencent Files/QQ号/FileRecv",
    "delete_scanned_files_after_scan": false
  }
}
```

如果希望扫描后删除由 Bot 下载的文件，再把 `delete_scanned_files_after_scan` 改成 `true`。

## 启动监控

先 dry-run 观察日志，不发群消息：

```powershell
python -m safebot run --config config/settings.json --dry-run
```

确认窗口和 selector 都正确后再真实发送：

```powershell
python -m safebot run --config config/settings.json --send --yes
```

建议在 `settings.json` 里设置 `monitored_window_titles`，只监控明确的群窗口，避免误发。

如果希望自动监控所有已打开的 QQ 独立聊天窗口，把 `monitored_window_titles` 和 `window_title_keywords` 都设为空列表。程序会排除标题正好为 `QQ` 的主窗口，并在每轮轮询时重新发现窗口。

## 评分规则

总分封顶 100，等级为：

- `0-20`：安全，不播报
- `21-50`：低风险
- `51-80`：中风险
- `81-100`：高风险

实现中的分值与任务书一致：VirusTotal 1-2 命中 +30、3 个以上 +60；Safe Browsing 命中 +80；新域名 +15；HTTPS/证书异常 +10；仿冒登录 +40；可疑 JS/隐藏 iframe/跳转 +20；文件伪装 +50；Office 宏 +35；PDF JS +30；压缩包含可执行文件 +45。

## 注意

- 免费 VirusTotal API 默认 4 次/分钟，代码内置限速。
- Safe Browsing 文档要求 `threatMatches.find` 最多一次查 500 个 URL，本项目按单 URL 查询。
- 本地规则会用 `requests` 下载 HTML 但不执行 JavaScript。
- UIAutomation 只能读到当前可见/已加载的消息，历史消息需要额外滚动逻辑。
- QQ 富媒体卡片可能只在无障碍树里暴露标题、来源和卡片类型，不暴露原始 URL。代码会额外扫描控件属性中的 URL；如果卡片完全不暴露 URL，只能记录日志，无法对真实目标链接打分。
