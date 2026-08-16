# GitHub 项目审查

`GitHub Project Review` · `github-project-review`

面向有 Agent 协作的普通用户，只读审查公开 GitHub 项目，并用简短、易懂的方式回答：

- 这个项目有没有兑现自己的功能；
- 它能帮你做什么；
- 是否值得采用；
- 最需要注意的风险是什么。

默认不克隆、不安装、不编译、不运行目标项目，也不会擅自使用账号、Cookie、API Key 或 GitHub Token。

## 主要能力

- 审查单个项目或批量比较多个项目；
- 区分桌面应用、命令行工具、网页服务、开发库、Agent Skill 等项目形态；
- 核对 README、源码、测试、Release 和公开安全通告；
- 判断 Windows、macOS、Linux 兼容性，但没有实际差异时不打扰用户；
- 对 Agent Skill 仓库检查 `SKILL.md`、插件清单和高影响指令；
- 用“可能发生什么 + 应该怎么做”解释风险，避免向普通用户倾倒代码细节。

## 使用方式

将 [`skills/github-project-review`](skills/github-project-review) 目录添加到支持 Agent Skills 的 Agent 中，然后提供一个或多个公开 GitHub 链接，例如：

```text
使用 GitHub 项目审查：
https://github.com/owner/repository
```

默认输出只保留采用建议、实际用途和一个最重要的风险。用户要求详细依据时，再展开源码、Release、Issue 和安全证据。

## 审查层级

1. **快速审查**：读取仓库信息、README、最新版本、最近提交和公开安全通告。
2. **深度审查**：补充文件树、发布资产，以及高优先级安装文件、配置文件或 Agent 指令。
3. **采用前审查**：针对最终选择的项目重新确认版本、权限、风险和低风险验证方案。

## 内置采集器

Skill 附带只读 GitHub 证据采集器，仅使用 Python 标准库和公开 GitHub API：

```powershell
python skills/github-project-review/scripts/collect_github_evidence.py `
  --url https://github.com/owner/repository `
  --mode deep `
  --out github-evidence.json
```

采集器默认匿名访问。只有用户明确同意并添加 `--use-token` 时，才会读取环境中的 `GITHUB_TOKEN`。

## 验证

```powershell
python -B -m unittest discover -s skills/github-project-review/tests -v
```

## 限制

- 只审查公开 GitHub 仓库；
- 静态筛查不能证明项目绝对安全；
- 默认不执行完整依赖漏洞扫描、所有权变更审计或运行验证；
- GitHub API 限流或关键代码不可见时，会降低结论置信度。

## License

[MIT](LICENSE)
