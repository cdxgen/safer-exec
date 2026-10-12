# safer-exec and Eclipse Enclave

This note compares safer-exec 1.1.0 with [Eclipse Enclave](https://github.com/eclipse-enclave/enclave) at commit `86b7538` (9 October 2026). Enclave was studied by reading its source and documentation; it was not built or run. Enclave ships as a rolling prerelease and changes weekly, so file paths are given for the claims most likely to drift.

## The short version

The two projects work at different layers.

**safer-exec confines a single command.** A caller asks it to run `npm install` or `bash -c '…'`: a Node.js program, the CLI, or an agent harness hook. The Go engine then wraps that one process tree in whatever the host kernel offers:

- Linux: namespaces, Landlock, seccomp and cgroups.
- macOS: a Seatbelt profile.
- Windows: an MXC process container inside a job object.
- OpenBSD: `pledge` and `unveil`.

Policies name individual paths, hosts and ports. Resource limits are built in. The engine can also audit, learn from, dry-run and diff what the command did.

**Enclave confines a whole agent session.** It builds a Debian image containing Claude Code, Codex or another agent CLI, then runs it in a Docker or Podman container with the project bind-mounted. A privileged gateway container sits in front of the session's network. The agent's own permission prompts are switched off by default. Isolation comes from the container runtime. Enclave's own engineering goes into three areas:

- the network gateway: DNS filtering, an IP set and a transparent proxy that can intercept TLS;
- credential handling;
- day-to-day agent comfort: logins, memory, skills and IDE links.

Neither is a superset of the other.

- Enclave has no resource limits, no file or exec audit, and no native isolation on macOS or Windows.
- safer-exec has no concept of an agent session, does not broker secrets, and never intercepts TLS.

## At a glance

| | safer-exec | Enclave |
|---|---|---|
| Unit of isolation | One command and its children | A whole agent session: the agent CLI, its shells and everything they start |
| Who provides isolation | Kernel features, called directly on each OS | Docker/Podman container defaults, a gateway sidecar, an experimental QEMU microVM |
| Linux | User, mount, PID, UTS and network namespaces; `pivot_root`; Landlock (files and TCP ports); seccomp-bpf; cgroup v2 | Container namespaces with Docker's default seccomp and AppArmor; no profile of its own |
| macOS | Seatbelt via `sandbox-exec`, plus rlimits; no VM | Containers in Docker Desktop's Linux VM |
| Windows | MXC process container (BaseContainer filesystem grants, per-container WFP firewall) inside a job object | `enclave.exe` forwards to the Linux CLI in WSL2; Docker runs there |
| OpenBSD | `pledge` and `unveil` | Not supported |
| Privilege needed | None on macOS and Windows. Unprivileged user namespaces on Linux (an AppArmor profile on Ubuntu 24.04+) | Access to a rootful Docker daemon, which is root-equivalent, or rootless Podman |
| Filesystem policy | Read, write and deny path lists | The set of bind mounts; project mounted read-write or read-only |
| Network policy | Ports, resolved IPs, hostnames through a CONNECT proxy, URL rules (Linux, audit only) | Domain allowlist enforced by DNS, an IP set and a transparent HTTP/TLS proxy |
| Resource limits | Memory, CPU, process count, disk I/O (Linux), wall-clock timeout | None |
| Secrets | Environment scrubbing and explicit pass-through | Random placeholders that the gateway swaps for real credentials |
| Audit | File, exec, network and proxy events; filesystem diff | Network log of HTTP, TLS and DNS decisions |
| Learn and dry-run | Yes | No |
| Interfaces | Node.js library, CLI, agent harness hooks | CLI with JSON output |
| Distribution | npm with per-platform engine packages; standalone binaries | `.deb`, `.rpm`, standalone binaries, Scoop; a rolling prerelease |
| License | MIT | MIT (an Eclipse Foundation project) |

## Architecture

### safer-exec

The Node.js layer does three things:

- resolves the policy (built-in ecosystem policies, policy files and imported harness permissions);
- resolves allowed hostnames;
- writes a JSON `ExecConfig` to the Go engine, `safer-exec-rt`, on stdin.

The engine then confines the command with the native mechanism for the host OS:

- **Linux:** it re-executes itself into new namespaces, builds a tmpfs root out of bind mounts and pivots into it, then applies Landlock, seccomp and cgroup limits before `execve`.
- **macOS:** it generates a deny-by-default Seatbelt profile and runs the command under `sandbox-exec` with rlimits.
- **Windows:** it translates the config into an MXC request and starts Microsoft's `wxc-exec.exe` suspended inside a job object that carries the limits.

Results come back as marker-prefixed JSON on stdout and audit lines on stderr. No daemon is involved, and nothing outlives the command.

### Enclave

The `enclave` CLI on the host takes these steps:

1. Merges configuration from three sources: global settings, per-project settings (kept outside the worktree), and command-line flags.
2. Builds a per-tool image. It rebuilds when the image inputs change or the agent CLI has an update.
3. Prepares bind mounts and persistent stores.
4. Resolves the network policy into an allow set and a deny set.
5. Starts the gateway container: Alpine with dnsmasq, iptables/ipset and a Go proxy, holding `NET_ADMIN` and `NET_RAW`. It waits for the gateway to report ready.
6. Starts the tool container inside the gateway's network namespace (`--network container:<gateway>`).

The tool container runs as a non-root `agent` user whose UID matches the host user. It uses `no-new-privileges`, a tmpfs over `/etc/sudoers.d` and `--init`; `internal/backend/docker/docker.go` lists the whole hardening set. Enclave drives the engine by shelling out to the `docker` or `podman` CLI. On exit the tool container is removed and the gateway stopped. The experimental QEMU backend boots an Alpine microVM instead; it has user-mode networking and no egress control.

### What the difference means in practice

- **Policy granularity.** safer-exec gives each command its own policy. For example, `npm install` can reach the registry while the test run that follows has no network at all. Enclave applies one policy to everything in the session. That policy can be changed while the session runs (`enclave network apply`).
- **The agent itself.** Under Enclave, everything the agent does happens inside the container, including its own file edits and web fetches. With safer-exec's harness hooks, the agent stays on the host. Hooks record every tool call and can deny calls by rule, and `--wrap` runs shell commands in the sandbox. The agent's built-in file and web tools still run with the user's rights.
- **Boundary.** Both rely on the host kernel. Enclave's documentation says it is "not a hardened container escape boundary". safer-exec on Linux layers seccomp and Landlock on top of namespaces. On macOS and Windows it relies on Seatbelt and BaseContainer respectively.
- **Footprint.** Enclave needs a container engine, image builds and two containers per session. safer-exec needs only its own binary, plus MXC's executor on Windows.

## Feature by feature

### Filesystem

| | safer-exec | Enclave |
|---|---|---|
| Model | Kernel-enforced allow-lists of read and write paths | Bind mounts into a container image |
| What the sandbox sees by default | Linux: a tmpfs root with granted paths and system directories. macOS: system directories plus granted paths, and file metadata everywhere. Windows: granted paths plus a read-only `%SystemRoot%` | The image, plus the project, persistent stores, caches, a copy of `~/.gitconfig` and a few read-only extras |
| Granularity | Any path, read or write | Per mount: project read-write (default) or read-only, plus extra directories |
| Deny rules | Granted paths that contain hidden components are dropped unless `allowHidden` is set. `denyPersistenceWrites` blocks launch agents, shell rc files and Startup folders; on Windows it uses native deny entries, which can only cover locations that already exist | None inside a mount. Instead Enclave refuses to mount `$HOME`, hidden entries in `$HOME`, XDG and `~/Library` data, its own state, or the SSH agent socket (`internal/mounts/sensitive.go`) |
| Repository metadata | No special handling | `.git/config` and related config files are mounted read-only even in a writable project. Hooks can still be written, which the docs list as a known gap |
| Scratch space | `privateTmp`, `protectHome=tmpfs`, overlayfs `tmpOverlayPaths` (Linux) | Image filesystem; nothing copy-on-write over the project |
| Change tracking | `--diff` reports added, modified and deleted files with content hashes | None |
| Mount hardening | Optional fd-based bind mounts with TOCTTOU checks, read-only submount enforcement, `/proc` and `/dev` hardening (Linux) | Mount sources resolved through symlinks before the sensitive-path check |

### Network

| | safer-exec | Enclave |
|---|---|---|
| Default | Whatever the caller allows; built-in policies list their registries | Restricted to the tool's allowlist, which includes broad CDN domains |
| No network | `disableNetwork`: a new network namespace on Linux, a Seatbelt deny on macOS, all inbound and outbound traffic blocked on Windows | No dedicated switch; unrestricted mode removes the gateway entirely |
| By hostname | `proxyEgress`: a loopback CONNECT proxy matches exact names or dot-boundary suffixes. macOS and Windows confine all other egress to the proxy, so clients that ignore proxy settings fail closed. Linux enforces this only when no extra ports are allowed | dnsmasq answers only for allowed names and adds the answers to an IP set. Ports 80 and 443 are redirected to a proxy that checks Host and SNI. This works for clients that ignore proxy settings |
| Subdomains | Suffix matching on a dot boundary | A bare domain covers its subdomains; wildcards are rejected |
| By IP or CIDR | `allowIPs`: enforced per address on Windows (WFP); port-only on macOS and Linux | Not supported |
| By port | `allowPorts`: Landlock, Seatbelt or WFP | Not supported. An allowed IP is reachable on every port and protocol, UDP included |
| URL paths and methods | `allowUrls` on Linux flags violations from eBPF TLS tracing; it does not block | Not supported; the docs call the allowlist "destination policy, not content policy" |
| TLS interception | Never | Only where needed: to release secrets, or for every allowed host with `--network-log=requests`. Uses a local CA valid for ten years |
| DNS | Allowed names are resolved before launch; the sandbox uses the host resolver | dnsmasq inside the gateway forwards allowed names to one upstream resolver (8.8.8.8 by default) and blackholes the rest |
| IPv6 | Supported in rules | Disabled in the gateway |
| Inbound | `allowListen`; binding is blocked by default, loopback included | Published ports, host port bridging, OAuth callback forwarding |
| Changing policy mid-run | No; the policy is fixed per run | `SIGHUP` reload with an atomic IP-set swap and rollback |
| Failure behavior | The proxy fails closed; `strict` turns any degraded control into an error | The gateway drops all egress and exits if dnsmasq or the proxy dies |

### Processes and execution

| | safer-exec | Enclave |
|---|---|---|
| Exec control | `allowExec`, `blockExec`, `blockFork`, `maxProcesses`; macOS `blockInterpreters`; Linux `blockJIT` | None. The agent runs with its permission prompts disabled (Claude's `--dangerously-skip-permissions`, Codex's bypass flag) unless `--no-yolo` is given |
| Syscall filtering | Default seccomp blocklist (ptrace, mount, unshare, bpf, io_uring, module loading and more), plus user-supplied Kafel or BPF filters (Linux) | Docker's default profile |
| Privilege | No new privileges. Namespaced root is optionally mapped back to the caller (Linux) | Non-root user, `no-new-privileges`, sudo masked. `--admin` restores apt/dpkg sudo; `exec --admin` gives a root shell |
| Lifetime | Timeout, kill when the parent dies, PID 1 reaper (Linux), kill-on-close job (Windows) | Removed on exit, or kept running in the background and attachable later |
| Execution tracing | `traceExec` records child processes | None |

### Resource limits

safer-exec limits memory, CPU, process count and wall-clock time on every supported OS. It uses cgroup v2 or v1 on Linux, rlimits on macOS and a job object on Windows. It can also throttle disk I/O on Linux. Enclave sets no limits on the Docker or Podman backends. A runaway build inside a session can use all the memory, CPU and PIDs the Docker host has. The QEMU backend fixes one vCPU and at least 4 GiB of memory.

### Environment and secrets

| | safer-exec | Enclave |
|---|---|---|
| Host environment | Not inherited, apart from a short safe baseline (PATH, HOME, locale and the like) | Not forwarded, apart from terminal and timezone settings |
| Scrubbing | Names that look like credentials and loader-control variables (`LD_*`, `DYLD_*`, `NODE_OPTIONS`, .NET profilers and so on) are stripped unless listed in `allowEnvs`. The Go engine repeats the check | Reserved names are protected. The project's `.env` file is loaded into the container, so the repository controls part of the environment |
| Credential brokering | None. A secret given to a command is visible to it | Credentials that have a `serviceAuth` rule reach the container as a random placeholder. The gateway swaps in the real value, but only in HTTPS request headers to the declared hosts; plaintext or other hosts get a 403 |
| Login state | Not applicable | Per-tool OAuth stores shared across projects by default and readable by the agent |

### Observability

| | safer-exec | Enclave |
|---|---|---|
| Audit trail | File reads and writes, exec, network, and proxy connects and denials. Sources: Seatbelt traces (macOS), seccomp traps and LSM BPF (Linux), MXC denial capture (Windows, partial) | JSON-lines network log: HTTP, TLS connection, DNS and session events with verdict and matching rule. Query strings are never logged |
| Learning | `--learn` writes a policy file from observed behavior, ready for the next enforced run | None |
| Dry run | A deny-everything run that reports what the command tried to do | None (`--dry-run` exists only for clean-up and extension commands) |
| Filesystem diff | Yes | None |
| Crypto | TLS cipher and library tracing with a CycloneDX CBOM; FIPS detection (Linux) | None |
| Session status | Not applicable | `ps --json`, and `status --json` snapshots of the agent's terminal |
| Telemetry | None | None from Enclave; it also switches off each agent's telemetry |

### Policy and configuration

safer-exec is configured through a fluent API, CLI flags or JSON policy files. Policy files round-trip: learn, prune, then enforce. Built-in policies cover npm, pnpm, Yarn, Bun, Deno, PyPI, uv, Maven, Go modules, Cargo, RubyGems, Composer and NuGet. Harness permission rules from Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, droid and OpenCode can be imported into a policy. `strict` turns every silently degraded control into an error.

Enclave reads a global `config.json` and a per-project one. The per-project file lives outside the worktree, and it can only tighten security settings, never widen them. A `network.jsonc` file sets network policy, and each tool has a dnsmasq-style allowlist. Extensions are described in `spec.yaml` files that follow Docker's experimental sandbox kit format, and their git provenance is recorded. `enclave config --view source` shows where each setting came from.

### Agent integration

| | safer-exec | Enclave |
|---|---|---|
| Model | Hooks into the agent's own tool calls; the agent runs on the host | Runs the agent CLI inside the container |
| Agents | Claude Code, ZCode, Codex, Gemini CLI, Cursor, droid, Copilot CLI, OpenCode | Claude Code, Codex, OpenCode, Pi, Mistral Vibe; Theia IDE |
| Per-call decisions | Audit every tool call. Enforce the harness's imported allow, ask and deny rules. Re-run shell commands inside the sandbox (`--wrap`) | None; one policy for the whole session |
| Agent comfort | Not in scope | Persistent logins with coordinated token refresh, per-project memory, skills, IDE and MCP bridging, Playwright MCP, background sessions, image inbox |

### Platforms, packaging and project health

| | safer-exec | Enclave |
|---|---|---|
| Languages | Go engine (about 18k lines, with about 11k lines of tests) and Node.js (about 10k lines, with about 9k lines of tests) | Go (about 51k lines, with about 50k lines of tests) and about 5k lines of shell |
| Tests of real isolation | Engine tests run real sandboxes on Linux and macOS CI; Windows jobs are added in this release | Mostly unit tests with stubbed Docker calls; live smoke tests are manual scripts |
| Releases | Versioned npm releases | Rolling prerelease (0.1.x) with no stable line |
| Artifacts | npm packages per OS and CPU; standalone binaries with checksums | `.deb`, `.rpm`, standalone binaries (unsigned, not notarized), Scoop; SHA-256 checksums; digest-pinned base images and SHA-pinned actions |

## Strengths and weaknesses

### safer-exec

**Strengths**

1. **Native on each OS.** No daemon, VM or image is needed. It runs directly on macOS, Windows, Linux and OpenBSD hosts and in CI jobs without Docker.
2. **A policy per command.** Each command gets the least access it needs. A package install and a test run can have different file and network rights within the same task.
3. **Resource limits on every platform.** It covers memory, CPU, process count and time, plus disk I/O on Linux.
4. **Observability.** Audit, learn, dry-run, filesystem diff, exec tracing and crypto tracing make the "observe, then lock down" workflow practical.
5. **Defense in depth on Linux.** A seccomp blocklist, Landlock, namespaces, and `/proc` and `/dev` hardening layer on top of each other.
6. **Embeddable.** The Node.js API and the ecosystem policies make it easy to put inside build tools such as cdxgen. Harness hooks add sandboxing to agents without replacing how they work.
7. **Address-level egress on Windows.** The per-container WFP rules restrict egress to specific addresses, which macOS and Linux cannot do without the proxy.

**Weaknesses**

1. **Guarantees vary by OS.** The capability matrix has many "Partial" and "No" entries. On macOS and Linux, egress without the proxy is filtered by port, not by host. On Linux, hostname filtering through the proxy is advisory once extra ports are allowed.
2. **Several hardening controls are opt-in.** These include fd-based mounts, submount enforcement, `/proc` hardening and `protectSystem`, so the default setup is weaker than the threat model's best case.
3. **Agent coverage stops at shell commands.** The agent process and its built-in file and web tools run unsandboxed. Hook enforcement fails open by design, and command-pattern rules have documented bypasses that only `--wrap` closes.
4. **No secret brokering.** Any credential handed to a sandboxed command can be read by it.
5. **Linux full isolation needs unprivileged user namespaces.** Inside a default Docker container, or on hardened distributions, it drops to a reduced mode in which the host filesystem is visible.
6. **Windows is new and narrow.** It needs a recent Windows 11 client build (not Windows Server) and depends on MXC, itself an early project. Audit and learn give only partial results there, and the built-in ecosystem policies still name macOS and Linux paths.
7. **A large configuration surface.** Dozens of options interact, and learning them takes time.

### Enclave

**Strengths**

1. **Whole-session containment.** Everything the agent does stays in the container, including its own file edits and fetches. Nothing depends on the agent's permission system or on hooks.
2. **A robust egress gateway.** Clients that ignore proxy settings are still caught by the DNS blackhole and transparent redirect. TLS connections are re-dialed to the SNI name rather than the IP the client chose. Reloads are atomic, and failures shut egress.
3. **Secrets the agent never sees.** The placeholder swap keeps API keys out of the container for any service with a `serviceAuth` rule.
4. **Careful host-protection defaults.** It refuses to mount home and dotfile directories, refuses to run as root, keeps project configuration outside the worktree where it can only tighten security, and mounts git config files read-only.
5. **Agent comfort.** Persistent logins, memory, skills, IDE and MCP bridging, background sessions and JSON status for orchestrators make long autonomous runs practical.
6. **An extension model with provenance.** Installing an extension shows what it will be allowed to do before it is added.
7. **Build hygiene.** Base images are pinned by digest, actions by SHA, and agent CLIs are installed without running npm lifecycle scripts.

**Weaknesses**

1. **No resource limits.** A runaway or hostile build can exhaust the Docker host.
2. **Isolation is whatever the container runtime gives by default.** Enclave sets no custom seccomp or AppArmor profile, drops no capabilities and does not make the root filesystem read-only. Under rootful Docker without `userns-remap`, container root is host root. The docs disclaim escape resistance.
3. **Writes go straight to the real project.** The project is writable by default and the agent runs without prompts. It can rewrite the repository, including git hooks that later run on the host, and nothing records what changed.
4. **Coarse network policy.** Rules work at domain level only.
   - An allowed IP is reachable on any port and over UDP, so QUIC is neither proxied nor logged, and SSH on port 22 is never logged.
   - The default allowlists include broad CDN domains: `cloudflare.com`, `fastly.net`, `akamaized.net` and `googleapis.com`.
   - There are no IP, CIDR or port rules, and IPv6 is switched off rather than filtered.
5. **TLS interception needs a long-lived local CA.** Releasing secrets or logging individual requests means trusting a ten-year CA inside the container.
6. **Little visibility beyond the network.** There is no file or exec audit, no learning, no dry run and no diff.
7. **A heavy footprint.** It needs root-equivalent Docker access, image builds and two containers per session. On macOS and Windows it works only through a VM (Docker Desktop or WSL2).
8. **A young project.**
   - Releases are a rolling 0.1.x prerelease with unsigned binaries, and real container behavior is tested by manual scripts.
   - Some docs disagree with the code. `exec --admin` is described as limited sudo but gives a root shell, and the architecture diagram shows a per-session network that the code never creates.
9. **One policy for everything.** A session cannot allow the network for `npm install` and deny it to the tests that follow.

## Using them together

The tools can be layered, with one caveat. safer-exec can run inside an Enclave session to add per-command limits, exec rules and a filesystem diff. However, Docker's default seccomp profile blocks the user namespaces that safer-exec's full Linux mode needs. It therefore falls back to reduced isolation: Landlock and seccomp without a private filesystem view. Its cgroup limits also need a delegated cgroup inside the container. The two network layers add up: Enclave's gateway filters by domain, and safer-exec can narrow ports or cut the network for a single command.

## What safer-exec could learn from Enclave

- **Credential placeholders.** safer-exec already runs an egress proxy. Swapping placeholders for real credentials would keep API keys away from the sandboxed command. It would require TLS interception for the hosts involved, which is a trust decision worth making explicit rather than by default.
- **Transparent egress capture on Linux.** Redirecting the sandbox's traffic to the proxy inside its own network namespace would make hostname rules hold for clients that ignore `HTTPS_PROXY`. Today Linux falls back to port rules.
- **Resolving inside the policy.** A resolver that answers only for allowed names, and pins exactly the addresses it returned, would close the gap between resolving a host before launch and connecting to it later.
- **Refusing dangerous grants.** Enclave refuses to mount the home directory, `~/.ssh`, `~/.aws` or cloud credential folders unless the user overrides it explicitly. Doing the same would stop an over-broad grant before it happens. safer-exec's hidden-path filter covers part of this today.
- **Policy that a project cannot loosen.** Enclave keeps project settings outside the worktree and lets them only tighten. safer-exec could apply the same idea to policy files found in a repository.
- **A session mode for agents.** Running the whole harness under safer-exec, not just its shell commands, would close the biggest gap that Enclave's design avoids.

## Method

- **Enclave:** commit `86b753832fd24d367ae93b59e6c6ad805a17c65b`. The Go sources, shell entrypoints, Dockerfiles, extension specs and the `docs/` tree were read; nothing was executed. Line counts come from that checkout; contributor and commit counts come from the GitHub API on 12 October 2026.
- **safer-exec:** this repository at version 1.1.0, cross-checked against the capability matrix in the README and the threat model.
