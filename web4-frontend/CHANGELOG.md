# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-03-05

### Added

- 建立发布前检查脚本 `scripts/release-preflight.sh`，并输出 `run/release-preflight-report.txt`。
- 建立发布准备脚本 `scripts/release-ready.sh`，串联版本号、changelog 与发布前门禁。
- CI 支持在 workflow 中强制开启 E2E（通过 `CI_RUN_E2E=1`）。
