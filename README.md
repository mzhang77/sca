# SCA：跟踪分支的依赖漏洞扫描

手动触发，一个入口 `bin/run.sh`，每次按顺序做两步：
1. **分支**：更新被跟踪的分支 -> 用 OSV-Scanner 扫依赖漏洞（Go + Rust + npm）-> （可选，缺省关闭）Go 用 govulncheck 标可达性 -> 每个分支生成**完整报告** -> 清理旧记录 -> `results/report-branches-latest.md`。
2. **镜像**：用 Trivy 扫交付镜像 -> 和第 1 步刚更新的分支源码比较（源码是否已修复）-> `results/report-images-latest.md`。

一步失败不影响另一步。没有"新增/旧"的对比：每次运行都给出各分支**当前**的全部漏洞。通知渠道只有日志文件；没有定时任务，不发任何外部消息，不安装任何软件。

## 安装与首次使用
1. 安装工具：`git`、`python3`（>= 3.8，只用标准库）、`curl`、[`osv-scanner`](https://github.com/google/osv-scanner) v2.x（分支扫描）、[`trivy`](https://github.com/aquasecurity/trivy)（镜像扫描）。
   可选：`go` + `govulncheck`（Go 可达性分析，缺省关闭；`bin/cleanup.sh` 清 Go 缓存时也会用 `go env`）。macOS 上可以 `brew install osv-scanner trivy`。
2. 复制配置并按需修改：
   ```
   cp config/branches.conf.example config/branches.conf    # 要跟踪的分支
   cp config/images.conf.example   config/images.conf      # 要扫的交付镜像
   cp config/settings.env.example  config/settings.env     # 可选：PATH、超时、保留数量等设置
   ```
   `settings.env` 可以不建，没有时全部用默认值（和 example 里的值相同，只有 `EXTRA_PATH` 默认为空）。常用的本机设置：工具装在非标准位置时加 `EXTRA_PATH`；
   项目放在外置盘上时设 `REQUIRED_MOUNT`（未挂载就不运行）。
3. `bin/check_env.sh` 检查工具和配置是否齐全，然后先用最小的仓库试跑：`bin/run.sh --only kvproto`。

`repos/ worktrees/ caches/ results/ logs/ state/` 都是运行时自动创建的，不进 git（见 `.gitignore`）。
Go 缓存默认放在项目里的 `caches/go-build`、`caches/go-mod`，只在 SCA 运行时生效，不影响你机器上其他 Go 项目（可用 settings.env 的 `GO_BUILD_CACHE` / `GO_MOD_CACHE` 改位置）。首次运行要完整下载各仓库，TiDB / TiKV 较慢（`CLONE_TIMEOUT` 默认 1 小时）。
macOS 和 Linux 都可以运行（脚本保持 bash 3.2 兼容）；防睡眠用的 `caffeinate` 只在 macOS 上有，其他系统只记一条 WARN。

## 日常使用
```
bin/check_env.sh              # 检查工具是否齐全（只检查，缺什么会告诉你怎么装）
bin/check_env.sh --selftest   # 装好 osv-scanner 后，用一个小 go.mod 验证输出格式能被解析
bin/run.sh                    # 先跑全部分支，再扫全部镜像，出两份报告
bin/run.sh --only kvproto     # 只跑一个分支（以及以它为源码的镜像）；也可以写镜像名，如 --only br
bin/run.sh --no-sync          # 不 fetch（快速试跑）
bin/run.sh --govulncheck      # 本次打开 Go 可达性分析（缺省关闭，见下）
bin/run.sh --skip-db-update   # 不更新 Trivy 漏洞库
bin/run.sh --branches-only    # 只做第 1 步（排查用）
bin/run.sh --images-only      # 只做第 2 步，和 worktree 现有内容比较（排查用）
tail -f logs/alerts.log       # 只看错误和警告
bin/cleanup.sh                # 删除本地所有分支（repos/ worktrees/）并清空本项目的 Go 缓存（caches/）；--dry-run 只看不删，-y 不询问
```
退出码：0 = 全部成功；1 = 有失败；2 = 前置条件不满足；3 = 已有实例在运行。

## 看结果
- **results/report-branches-latest.md**（分支报告）：所有分支当前漏洞的汇总（每次运行后覆盖更新）。0) Go 官方近期修复命中分支（golang.org/x/* 和标准库，近 `GO_OFFICIAL_DAYS` 天，按公布日期倒序，和镜像报告第 0 节同口径）；1) 总览（每个分支一行）；2) 需要优先处理（在 CISA KEV 里，或 Go 可达），跨分支合并排序；3) 各分支按依赖包聚合的完整表。某分支本次失败或没运行时，显示它最近一次成功的结果并注明。
- **results/<名称>/<分支>/<日期_时分秒>/**：每次运行一个目录，含 `report.md / report.tsv / report.json`（完整报告）、`osv.json`、`govulncheck/`（原始输出）。`latest` 指向最近一次成功生成报告的目录。
- 报告列：依赖包 | 生态 | 当前版本 | 建议升级到 | CVE数 | 最高CVSS | 严重程度 | KEV | 可达性
  - 建议升级到：对该包每个 CVE 取"高于当前版本的最小修复版本"，再取其中最大值；OSV 里完全没有修复版本的 CVE 会注明"另有 N 个无修复"。
  - CVE数：按"同一漏洞"去重（GHSA/GO/RUSTSEC 编号与 CVE 别名合并计一个）。
  - KEV：YES = 在 CISA 已知被利用漏洞目录里（优先级最高）；`?` = 本次没能获取 KEV 数据。
  - 严重程度 UNKNOWN = OSV 里还没有 CVSS 评分（新披露的 CVE 常见），**不代表低危**；汇总总览里的"未评分"列统计了这类漏洞。
  - 可达性（仅 Go，**缺省关闭**：`config/settings.env` 里 `GOVULNCHECK_ENABLED=0`。客户扫的是镜像，商业扫描器只按版本匹配，不做可达性，所以缺省不跑；关闭时 Go 可达性一律为 unknown，“需要优先处理”只看 KEV）：called = 漏洞函数在调用链上；imported = 包被引入但漏洞函数没被调用；required = 仅模块被依赖；unknown = 没有 govulncheck 结果；n/a = 非 Go（Rust、npm 无可达性分析）。
  - 排序：KEV 优先，其次可达，再按 CVSS。

## 日志（logs/）
- `run-YYYY-MM-DD.log`：每次运行的完整日志；`git-*.log`：git 原始输出。
- `alerts.log`：只含需要关注的行，每行带 `[ALERT]`：
  - `[ERROR]`：某个分支没能完成（fetch 失败/超时、无法 fast-forward、worktree 有改动、扫描器报错/超时/输出非法…）。
  - `[WARN]`：降级但继续（缺 govulncheck、某个 go module 的 govulncheck 失败、KEV 下载失败改用缓存、RETENTION 非法…）。
- 每个阶段的失败都会写 `[ERROR]` 且退出码非 0；脚本被中断/崩溃有兜底告警；各分支互相隔离；同一时间只允许一个实例运行。
- 日志是唯一通道，所以每次手动运行后请看一眼终端末尾的汇总，或 `tail logs/alerts.log`。
- `logs/` 下的日志文件不会被自动清理。

## 目录
```
config/branches.conf   被跟踪的分支（名称 仓库URL 分支）——增删分支只改这里；从 branches.conf.example 复制，不进 git
config/images.conf     要扫的交付镜像（名称 镜像 对应分支名称）；从 images.conf.example 复制，不进 git
config/settings.env    PATH、超时、RETENTION、排除路径、REQUIRED_MOUNT、Go 缓存位置等设置；可选，从 settings.env.example 复制，不进 git
bin/                   run.sh(入口) lib.sh sync.sh scan.sh sca.py image_view.py check_env.sh cleanup.sh
repos/<owner>__<repo>.git        bare + blobless 仓库，只 fetch 被跟踪的分支
worktrees/<owner>__<repo>/<分支>/  每个分支一个 worktree（本地分支 sca/<分支>）
caches/go-build  caches/go-mod   本项目的 Go 编译缓存和模块缓存（go 第一次用到时自动创建）
results/  logs/  state/          结果 / 日志 / last_run.json 与 KEV 缓存
tests/                  test_sca.py（单元）  test_image_view.py（镜像，桩 trivy）  e2e.sh（本地假 origin + 桩扫描器，不联网）
```

## 旧记录清理（RETENTION，默认 10）
每次运行结束时，每个分支只保留 `results/<名称>/<分支>/` 下最新的 `RETENTION` 个扫描目录，更早的删除，并在运行日志里记一行 `retention=…: removed …`。
- **不分成败**：失败的运行目录也占名额。若连续失败超过 RETENTION 次，`latest` 指向的旧结果可能被清掉，此时汇总会如实写"本次失败，尚无成功结果"。
- 只清理 `branches.conf` 里现有的目标；已删除目标的旧结果不动。只删名字是时间戳格式的目录，不碰 `latest` 链接。
- `RETENTION` 不是 >= 1 的整数时只告警（`[WARN]`），不删除任何东西。

## 防止睡眠
运行期间自动用 `caffeinate -i -m -s -w <脚本pid>` 防止 Mac 睡眠，脚本结束时自动退出（`PREVENT_SLEEP=0` 可关闭）。`-s` 只在接电源时有效；合上笔记本盖子仍会睡眠，长时间运行（首次 TiDB/TiKV）请保持接电并开盖。

## 对仓库的安全约定
对 worktree 只做 `git merge --ff-only`。有本地改动、分支被强推、worktree 不在预期分支上时只报错，绝不 reset / clean / checkout -f。

## 已知限制
- Rust（TiKV）没有可达性分析，可达性列为 n/a。
- 扫描范围是仓库内所有被 OSV-Scanner 识别的清单（go.mod、Cargo.lock、npm 锁文件等），按 `EXCLUDE_PATH_REGEX` 排除不会编进交付二进制的清单（测试模块 tests/、integration_tests/，示例 examples/，以及 node_modules/testdata/third_party）。目的是让分支报告接近“这个分支 build 出的镜像会被扫出什么”；分支和已发布的镜像不一致是正常的（镜像可能是旧 build），两边都不一定是错；`dev` 依赖组默认忽略（若 OSV 输出携带依赖组）。
- govulncheck 需要能编译这些仓库：首次会下载 Go 模块并可能切换 Go 工具链（TiDB 较慢）；用较旧 Go 编译的 govulncheck 可能解析不了新版 Go 的代码，此时只会产生 WARN，可达性为 unknown。
- stdlib 的漏洞按 go.mod 的 `go` 指令版本匹配 OSV，可达性按实际工具链版本匹配 govulncheck，两者可能不同。
- kvproto 这类被 TiDB/TiKV 引用的库，最终生效的依赖版本由消费方的 go.mod / Cargo.lock 决定，其结果更多反映"该分支自己声明的依赖偏旧"。

## 镜像报告（客户视角，bin/run.sh 第 2 步）
客户的商业扫描器扫的是交付的镜像，不是源码。`bin/run.sh` 在更新完分支后用 Trivy 扫 `config/images.conf` 里的镜像（默认 linux/amd64），
再把每个漏洞和对应分支的源码比较，找出“源码已修复、还没发镜像”的情况。
某个分支在第 1 步更新失败时，它对应的镜像仍会扫描，但对比的是该分支上次的内容，日志里会有 `[WARN] ... failed in step 1`。
- **results/report-images-latest.md**（镜像报告）：0) Go 官方近期修复命中镜像（golang.org/x/* 和标准库，近 `GO_OFFICIAL_DAYS` 天，按公布日期倒序）；1) 总览；2) 客户最可能提的（KEV，或 HIGH/CRITICAL 且有修复版本）；3) 近 N 天新公布的；
  4) 源码已修复、还没发镜像的；5) 源码也没修复的；6) 说明；最后是**附录：操作系统包**。
- 这份报告假设客户从分支自己 build 私有镜像，所以 OS 包不计入统计，只列在报告最后的附录里（单个镜像的 report.md 也一样）。
- **results/images/<名称>/<运行ID>/**：`trivy.json`（原始输出）、`report.{md,tsv,json}`。保留数量同样受 `RETENTION` 控制。
- 源码状态：源码已修复(待发镜像) / 源码未修复 / 源码已移除该依赖 / 暂无修复版本 / 无法对比 / 需重建镜像(OS包)。
  Go 依赖按二进制的主模块找到分支里对应的 go.mod 比较（同一个镜像里有多个二进制时取最需要关注的状态）；stdlib 按 go.mod 的 toolchain/go 指令比较。
- 镜像 tag 末尾带 commit（如 `v8.5.8-20261107-c1ce72e`）时，会显示镜像落后分支多少个 commit。
- 交付了新镜像后，改 `config/images.conf`。日志和分支共用 `logs/run-YYYY-MM-DD.log`，告警同样写入 `logs/alerts.log`；分支和镜像的结果目录用同一个运行ID。
- 已知限制：TiKV 是 Rust，二进制里没有依赖清单时 Trivy（以及客户的扫描器）只能看到 OS 包；Dashboard 前端（npm）嵌在 pd-server 里，镜像扫描看不到。
- 测试：`python3 tests/test_image_view.py`（桩 trivy，不联网）。

## License
MIT，见 [LICENSE](LICENSE)。
