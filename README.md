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

## CI 示例

```yaml
- name: Repository readiness
  run: python repo_doctor.py . --format sarif --output repo-doctor.sarif --fail-on-high
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: repo-doctor.sarif
```
