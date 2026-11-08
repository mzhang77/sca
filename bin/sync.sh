#!/usr/bin/env bash
# sync.sh - 仓库与 worktree 管理（被 run.sh source）。
# 布局：repos/<owner>__<repo>.git（bare + blobless，只 fetch 被跟踪的分支）
#       worktrees/<owner>__<repo>/<branch>/（每个分支一个 worktree，本地分支 sca/<branch>）
# 更新策略：只做 fast-forward。有任何无法安全处理的情况就报 [ALERT] ERROR 并原样保留，绝不 reset/clean/checkout -f。
# 成功后设置全局变量 WT（worktree 路径）和 SHA（当前 commit）。

sync_target() {  # name url branch
  local name="$1" url="$2" branch="$3"
  local rid repo bslug gitlog rc head remote lb to cur
  rid="$(repo_id_from_url "$url")"
  repo="$REPOS_DIR/$rid.git"
  bslug="$(slugify "$branch")"
  WT="$WT_DIR/$rid/$bslug"
  SHA=""
  lb="sca/$branch"
  gitlog="$LOG_DIR/git-$(date +%F).log"
  mkdir -p "$WT_DIR/$rid"

  if [ ! -d "$repo" ]; then
    log_info "[$name] first run: creating bare partial-clone repo for $url"
    { git init --bare -q "$repo" \
      && git -C "$repo" remote add origin "$url" \
      && git -C "$repo" config core.repositoryformatversion 1 \
      && git -C "$repo" config extensions.partialClone origin \
      && git -C "$repo" config remote.origin.promisor true \
      && git -C "$repo" config remote.origin.partialclonefilter blob:none; } >>"$gitlog" 2>&1
    if [ $? -ne 0 ]; then alert ERROR "[$name] cannot initialise repo $repo (see $gitlog)"; return 1; fi
  else
    git -C "$repo" remote set-url origin "$url" >>"$gitlog" 2>&1
  fi

  to="$FETCH_TIMEOUT"
  git -C "$repo" rev-parse -q --verify "refs/remotes/origin/$branch" >/dev/null 2>&1 || to="$CLONE_TIMEOUT"
  log_info "[$name] git fetch origin $branch (timeout ${to}s)"
  run_to "$to" git -C "$repo" fetch --no-tags --filter=blob:none origin "+refs/heads/$branch:refs/remotes/origin/$branch" >>"$gitlog" 2>&1
  rc=$?
  if [ $rc -eq 124 ]; then
    alert ERROR "[$name] git fetch timed out after ${to}s"; return 1
  elif [ $rc -ne 0 ]; then
    alert ERROR "[$name] git fetch failed (exit $rc): network/auth problem, or branch '$branch' was deleted/renamed upstream. See $gitlog"; return 1
  fi
  remote="$(git -C "$repo" rev-parse -q --verify "refs/remotes/origin/$branch^{commit}")" \
    || { alert ERROR "[$name] origin/$branch not found after fetch"; return 1; }

  if [ ! -e "$WT/.git" ]; then
    git -C "$repo" worktree prune >>"$gitlog" 2>&1
    log_info "[$name] creating worktree $WT"
    if git -C "$repo" show-ref --verify -q "refs/heads/$lb"; then
      run_to "$CLONE_TIMEOUT" git -C "$repo" worktree add -q "$WT" "$lb" >>"$gitlog" 2>&1
    else
      run_to "$CLONE_TIMEOUT" git -C "$repo" worktree add -q -b "$lb" "$WT" "refs/remotes/origin/$branch" >>"$gitlog" 2>&1
    fi
    rc=$?
    if [ $rc -ne 0 ]; then alert ERROR "[$name] git worktree add failed (exit $rc). See $gitlog"; return 1; fi
  fi

  cur="$(git -C "$WT" symbolic-ref -q HEAD)"
  if [ "$cur" != "refs/heads/$lb" ]; then
    alert ERROR "[$name] worktree is on '${cur:-detached HEAD}', expected refs/heads/$lb. Left untouched; fix manually."; return 1
  fi

  head="$(git -C "$WT" rev-parse HEAD)"
  if [ "$head" != "$remote" ]; then
    if ! git -C "$WT" merge-base --is-ancestor "$head" "$remote" 2>/dev/null; then
      alert ERROR "[$name] cannot fast-forward: local ${head:0:10} is not an ancestor of origin/$branch ${remote:0:10} (upstream force-push, or local commits). Nothing was changed; resolve manually."
      return 1
    fi
    if [ -n "$(git -C "$WT" status --porcelain --untracked-files=no)" ]; then
      alert ERROR "[$name] worktree has modified tracked files; refusing to fast-forward. Left untouched: $WT"; return 1
    fi
    run_to "$CLONE_TIMEOUT" git -C "$WT" merge --ff-only -q "$remote" >>"$gitlog" 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then alert ERROR "[$name] git merge --ff-only failed (exit $rc). See $gitlog"; return 1; fi
    log_info "[$name] fast-forwarded ${head:0:10} -> ${remote:0:10} ($(git -C "$WT" rev-list --count "$head..$remote") new commits)"
  else
    log_info "[$name] already up to date at ${head:0:10}"
  fi
  SHA="$(git -C "$WT" rev-parse HEAD)"
  return 0
}
