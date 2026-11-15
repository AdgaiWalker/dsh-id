/**
 * 为离线测试准备依赖软链接。
 *
 * 为什么需要：本插件依赖 DSH 提供的 @deepseek-ai/dsh-tools 与 @deepseek-ai/schemastery，
 * 它们已随 DSH profile 安装在磁盘上。测试不想联网安装，所以把 profile 里的包软链进来。
 *
 * 用法：
 *   node scripts/link-test-deps.mjs
 *   DSH_PROFILE=/path/to/profile node scripts/link-test-deps.mjs
 *
 * 安全性：只在本插件目录内创建 node_modules 软链接，不改动 profile 与任何用户数据。
 */

import { mkdir, symlink, rm, lstat } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pluginDir = resolve(__dirname, "..");

/**
 * 解析 profile 路径。
 * 注意：环境里可能已经存在一个相对值的 DSH_PROFILE（例如 "web"），
 * 那种情况要按 ~/.dsh/profiles/<name> 解析，不能当成相对当前目录。
 */
function resolveProfile() {
  const raw = process.env.DSH_PROFILE;
  if (!raw || !raw.trim()) return join(homedir(), ".dsh", "profiles", "web");
  const v = raw.trim();
  if (v.startsWith("/")) return v;                    // 绝对路径直接用
  const profilesRoot = join(homedir(), ".dsh", "profiles");
  const candidate = join(profilesRoot, v);            // 相对名 → profiles 下
  if (existsSync(candidate)) return candidate;
  return resolve(v);                                  // 兜底：相对当前目录
}

const profile = resolveProfile();

const PKGS = ["dsh-tools", "schemastery"];

async function main() {
  if (!existsSync(profile)) {
    console.error(`✗ DSH profile 不存在: ${profile}`);
    console.error("  用 DSH_PROFILE=/path/to/profile 指定正确的 profile。");
    process.exit(1);
  }

  const targetRoot = join(pluginDir, "node_modules", "@deepseek-ai");
  await mkdir(targetRoot, { recursive: true });

  let linked = 0;
  for (const pkg of PKGS) {
    const src = join(profile, "node_modules", "@deepseek-ai", pkg);
    if (!existsSync(src)) {
      console.error(`✗ 找不到 ${src}`);
      console.error(`  该 profile 里没有 @deepseek-ai/${pkg}，请确认 DSH 已正确安装。`);
      process.exit(1);
    }
    const dst = join(targetRoot, pkg);
    // 清理旧的错误软链接（例如相对路径写错的情况）
    try {
      const st = await lstat(dst);
      if (st.isSymbolicLink() || st.isFile() || st.isDirectory()) await rm(dst, { force: true, recursive: true });
    } catch { /* 不存在 */ }
    await symlink(src, dst, "dir");
    console.log(`  ✓ ${pkg} → ${src}`);
    linked++;
  }

  console.log(`\n已链接 ${linked} 个测试依赖（profile: ${profile}）`);
  console.log("现在可以运行: npm test");
}

main().catch((e) => {
  console.error("准备测试依赖失败:", e && e.message || e);
  process.exit(1);
});
