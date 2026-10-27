# Repo Doctor

一个离线运行的代码仓库发布前检查工具。它不上传源码，也不打印疑似密钥值；只输出文件、行号、规则和修复方向，适合在公开 GitHub、部署或交付前运行。

## 能做什么

- 检查私钥、GitHub Token、云访问 Key、模型 API Key 和高熵凭据赋值。
- 发现 `.env`、`application-local.*`、证书和凭据文件是否出现在仓库中。
- 识别 `package-lock.json`、`pom.xml`、`pyproject.toml` 等依赖入口。
- 根据仓库类型给出测试、构建和依赖审计命令建议。
- 输出终端摘要、JSON、Markdown 或 GitHub Code Scanning 可读取的 SARIF。
- `--fail-on-high` 可直接作为 CI 门禁。

## 使用

需要 Python 3.11+，无第三方依赖：

```powershell
python -m unittest discover -s tests -v
python repo_doctor.py C:\path\to\repo
python repo_doctor.py C:\path\to\repo --format markdown --output release-readiness.md
python repo_doctor.py C:\path\to\repo --format sarif --output repo-doctor.sarif --fail-on-high
```

工具会跳过 `.git`、依赖目录和构建产物，单个文件默认最多读取 2 MB。扫描结果是发布前检查，不替代完整的代码安全审计；误报或需要纳入组织规则时，可以在仓库层通过后续配置扩展规则。

## 扫描范围与结果

扫描的是当前目录中的文件，包括尚未提交和被 `.gitignore` 忽略的文件；不会读取 Git 历史，不跟随符号链接。报告中的“敏感文件”表示该文件存在，需要自行确认是否会进入提交。

检查结果只包含规则、路径、行号和位置指纹，不包含命中的凭据原文。JSON/Markdown 报告会包含扫描目录的绝对路径，分享前请确认其中没有个人目录信息。

退出码：正常完成为 `0`；指定 `--fail-on-high` 且发现高危项为 `1`；输入目录无效为 `2`。中危项会报告，但不会阻止 `--fail-on-high`。

规则识别部分已知 Key 前缀、私钥头和引号包围的凭据赋值，可能存在误报和漏报；不会验证 Key 是否有效，也不会联网查询依赖漏洞。依赖相关输出用于提示进一步审计，不代表依赖安全。

## CI 示例

下列 SARIF 上传步骤需要工作流具有 `security-events: write` 权限，并在有 Code Scanning 支持的仓库中运行。当前项目自身的 CI 运行测试、编译和扫描门禁。

```yaml
- name: Repository readiness
  run: python repo_doctor.py . --format sarif --output repo-doctor.sarif --fail-on-high
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: repo-doctor.sarif
```
