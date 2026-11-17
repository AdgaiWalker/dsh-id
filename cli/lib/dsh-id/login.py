#!/usr/bin/env python3
"""dsh-id login — 让 AI 自己完成一次网页登录：填账号密码 → 过 2FA → 存会话。

用法：
  dsh-id login github --url https://github.com/login --cred github-login --totp github-totp
  dsh-id login github --url ... --cred ... --totp ... --headless
  dsh-id login github --url ... --cred ... --method password --save

设计要点
--------
- 账号密码与 TOTP 种子都从保险库取（不解密到磁盘、不进 argv、不进日志）
- 每步截图落文件（路径写进输出），便于失败时定位卡在哪
- 成功后自动抓 storage_state 加密存成会话：dsh-id session use <名字> 即可复用
- 2FA 支持两种：TOTP 自动算码（--totp），或人工（--manual-2fa 时等你在窗口里点）
- 检测登录成功是启发式（跳转 + 是否还有密码框），不断言「一定登录成功」

退出码：0 成功 / 2 用法错 / 3 凭据缺失 / 4 填表失败 / 5 2FA 失败 / 6 未登录成功
"""
import argparse
import base64
import hashlib
import hmac
import os
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.expanduser("~/.local/lib"))
import vaultlib as V  # noqa: E402

SHOT_DIR = os.path.expanduser("~/.deepseekbot/vault/shots")

DEFAULTS = {
    "user": "input[type=email], input[name=login], input[name=username], input[autocomplete=username]",
    "pass": "input[type=password]",
    "submit": "button[type=submit], input[type=submit]",
    "otp": "input[autocomplete=one-time-code], input[name=otp], input[name=code], input[type=tel]",
}


def totp_code(seed, digits=6, period=30, offset=0):
    """RFC 6238 TOTP（SHA1）。offset 是时间步偏移，用来补偿时钟漂移（只允许 ±1）。"""
    s = str(seed).replace(" ", "").replace("-", "").upper()
    s += "=" * (-len(s) % 8)
    try:
        key = base64.b32decode(s, casefold=True)
    except Exception:
        raise SystemExit("dsh-id login: TOTP 种子不是合法 base32")
    counter = int(time.time()) // period + int(offset)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


def wait_fresh_step(period=30, min_left=5):
    """快到期就先等下一格：一秒钟后过期的码填进去就是失败，白记一次失败。"""
    left = period - (time.time() % period)
    if left < min_left:
        time.sleep(left + 0.5)


def otp_rejected(page, otp_sel):
    """码被拒的迹象：验证码框还在，或页面出现错误提示。"""
    try:
        if page.locator(otp_sel + ":visible").count() > 0:
            return True
        html = (page.content() or "").lower()
        for k in ("invalid code", "incorrect code", "code is invalid", "代码无效",
                  "验证码错误", "验证码不正确", "try again"):
            if k in html:
                return True
    except Exception:
        pass
    return False


def _login_breaker(name):
    """2FA 失败熔断：连错 2 次就停手（防止撞到平台锁号）。"""
    try:
        import guardlib as G
    except Exception:
        return None
    try:
        st = G.rate_check("login 登录", scope="login:" + name)
    except Exception:
        return None
    return None if st.get("decision") == "allow" else st.get("reason")


def _login_record(name, ok):
    try:
        import guardlib as G
        G.record("login 登录", ok=ok, scope="login:" + name)
    except Exception:
        pass


def shot(page, tag):
    os.makedirs(SHOT_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(SHOT_DIR, f"login-{int(time.time())}-{tag}.png")
    try:
        page.screenshot(path=path, full_page=False)
        os.chmod(path, 0o600)
        return path
    except Exception:
        return None


def looks_logged_in(page):
    """启发式：还有可见密码框 = 没登录；有登出/账号菜单 = 可能登录了。"""
    try:
        if page.locator("input[type=password]:visible").count() > 0:
            return False, "页面上还有密码框"
        html = (page.content() or "").lower()
        if any(k in html for k in ("sign out", "log out", "logout", "退出登录", "登出")):
            return True, "页面出现登出入口"
        return False, "没看到登出入口，也没密码框（不确定）"
    except Exception as e:
        return False, f"检测失败: {type(e).__name__}"


def fill_first(page, selectors, value, label):
    for sel in [s.strip() for s in selectors.split(",") if s.strip()]:
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible():
                loc.fill(value)
                return sel
        except Exception:
            continue
    raise SystemExit(f"dsh-id login: 找不到{label}输入框（试过: {selectors}）")


def main():
    ap = argparse.ArgumentParser(prog="dsh-id login")
    ap.add_argument("name", help="会话名（存下来后用 dsh-id session use <名字>）")
    ap.add_argument("--url", required=True, help="登录页 URL")
    ap.add_argument("--cred", required=True, help="凭据名（basic 类型，值形如 user:pass）")
    ap.add_argument("--totp", help="TOTP 种子所在的凭据名（可选）")
    ap.add_argument("--method", default=None, choices=["password", "totp", "manual"],
                    help="第二因素走法：totp=自动算码（默认，有 --totp 时）；"
                         "manual=人工在窗口里过；password=这个站没有第二步")
    ap.add_argument("--headless", action="store_true", help="无头模式（默认有头，便于人工接手）")
    ap.add_argument("--manual-2fa", action="store_true", help="2FA 不自动填，等你在窗口里操作")
    ap.add_argument("--wait-2fa", type=int, default=120, help="人工 2FA 最多等几秒（默认 120）")
    ap.add_argument("--no-save", action="store_true", help="只登录，不保存会话")
    ap.add_argument("--ttl-days", type=int, default=V.SESSION_TTL_DEFAULT)
    ap.add_argument("--user-selector")
    ap.add_argument("--pass-selector")
    ap.add_argument("--submit-selector")
    ap.add_argument("--otp-selector")
    args = ap.parse_args()

    method = args.method or ("totp" if args.totp else "manual")
    if method == "totp" and not args.totp:
        print("dsh-id login: --method totp 需要 --totp <种子名>", file=sys.stderr)
        raise SystemExit(2)

    # 登录档案：只记「怎么登」（URL/选择器/用哪个凭据），没有值。
    # 会话到期后 dsh-id session 靠它自动重登——这才是会话能短的前提。
    try:
        V.save_login_profile(args.name, {
            "url": args.url, "cred": args.cred, "totp": args.totp, "method": method,
            "headless": bool(args.headless),
            "user_selector": args.user_selector, "pass_selector": args.pass_selector,
            "submit_selector": args.submit_selector, "otp_selector": args.otp_selector,
            "ttl_days": args.ttl_days, "wait_2fa": args.wait_2fa,
        })
    except Exception as e:
        print(f"dsh-id login: 登录档案没存上（不影响这次登录）: {e}", file=sys.stderr)

    try:
        secret = V.load_secret(args.cred)
    except V.VaultError as e:
        print(f"dsh-id login: 取不到凭据 {args.cred}（{e.code}）", file=sys.stderr)
        raise SystemExit(3)
    if ":" not in secret:
        print("dsh-id login: 凭据值应为 user:pass（basic 类型）", file=sys.stderr)
        raise SystemExit(3)
    user, password = secret.split(":", 1)

    otp_seed = None
    if args.totp:
        try:
            otp_seed = V.load_secret(args.totp).strip()
        except V.VaultError as e:
            print(f"dsh-id login: 取不到 TOTP {args.totp}（{e.code}）", file=sys.stderr)
            raise SystemExit(3)


    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        venv_py = os.environ.get("DSH_ID_SESSION_PY") or os.path.expanduser(
            "~/.local/share/dsh-id session/venv/bin/python")
        if os.path.exists(venv_py) and os.environ.get("DSH_ID_LOGIN_VENV") != "1":
            env = dict(os.environ, DSH_ID_LOGIN_VENV="1")
            os.execve(venv_py, [venv_py, os.path.abspath(__file__), *sys.argv[1:]], env)
        print("dsh-id login: 没有 playwright（装一个或用 dsh-id session 的 venv）", file=sys.stderr)
        raise SystemExit(6)

    steps, ok, reason = [], False, ""
    with sync_playwright() as p:
        chrome = os.environ.get("DSH_ID_CHROME") or "/usr/bin/chromium"
        launch_kw = {"headless": args.headless, "args": ["--no-sandbox"]}
        if os.path.exists(chrome):
            launch_kw["executable_path"] = chrome     # 用系统 chromium，免下 playwright 自带包
        browser = p.chromium.launch(**launch_kw)
        ctx = browser.new_context()
        page = ctx.new_page()
        try:
            page.goto(args.url, timeout=90000, wait_until="domcontentloaded")
            steps.append(("打开登录页", shot(page, "01-login-page")))

            fill_first(page, args.user_selector or DEFAULTS["user"], user, "账号")
            fill_first(page, args.pass_selector or DEFAULTS["pass"], password, "密码")
            steps.append(("已填账号密码", shot(page, "02-filled")))

            page.locator((args.submit_selector or DEFAULTS["submit"])).first.click()
            page.wait_for_timeout(3500)
            steps.append(("已提交", shot(page, "03-after-submit")))

            otp_sel = args.otp_selector or DEFAULTS["otp"]
            if page.locator(otp_sel + ":visible").count() > 0 or "otp" in page.url.lower():
                use_manual = args.manual_2fa or method != "totp" or not otp_seed
                if use_manual:
                    print(f"需要 2FA：请在窗口里完成（最多等 {args.wait_2fa} 秒）…")
                    for _ in range(args.wait_2fa):
                        page.wait_for_timeout(1000)
                        if looks_logged_in(page)[0]:
                            break
                    steps.append(("人工 2FA 后", shot(page, "04-2fa-manual")))
                else:
                    breaker = _login_breaker(args.name)
                    if breaker:
                        print(f"dsh-id login: {breaker}", file=sys.stderr)
                        steps.append(("断路器已开", shot(page, "04b-breaker")))
                        raise SystemExit(7)
                    wait_fresh_step()          # 别用一个一秒钟后过期的码
                    passed = False
                    for attempt, offset in enumerate((0, 1)):
                        code = totp_code(otp_seed, offset=offset)
                        fill_first(page, otp_sel, code, "验证码")
                        steps.append((f"已填 TOTP（偏移 {offset:+d}）", shot(page, "05-totp-filled")))
                        page.locator((args.submit_selector or DEFAULTS["submit"])).first.click()
                        page.wait_for_timeout(4000)
                        steps.append(("提交 TOTP", shot(page, "06-totp-submit")))
                        if not otp_rejected(page, otp_sel):
                            passed = True
                            break
                        steps.append((f"第 {attempt + 1} 次被拒", shot(page, f"06b-rejected-{attempt + 1}")))
                    _login_record(args.name, passed)
                    if not passed:
                        print("dsh-id login: 2FA 两次都没过（已含 +1 步时钟补偿）。"
                              "停手，不再重试——继续撞会触发风控/锁号。", file=sys.stderr)
                        raise SystemExit(5)

            page.wait_for_timeout(1500)
            ok, reason = looks_logged_in(page)
            steps.append(("最终状态", shot(page, "07-final")))

            saved = None
            if ok and not args.no_save:
                state = ctx.storage_state()
                domain = urllib.parse.urlparse(page.url).netloc or urllib.parse.urlparse(args.url).netloc
                import json as _json
                meta = V.save_session(args.name, _json.dumps(state, ensure_ascii=False),
                                      domain, ttl_days=args.ttl_days,
                                      note="dsh-id login 自动登录后保存")
                saved = meta
                V.audit_event(action="login_save", cred=args.name, host=domain, path="-",
                              status=0, note="dsh-id login; cookies=%d" % len(state.get("cookies") or []))
        finally:
            if not args.headless and not ok:
                print("（窗口保留 20 秒便于你看现场）")
                page.wait_for_timeout(20000)
            browser.close()

    V.app_log("login", cred=args.name, ok=ok, shots=len(steps))
    for label, path in steps:
        if path:
            print(f"  {label}: {path}")
    if ok:
        print(f"✓ 登录成功（{reason}）")
        if saved:
            print(f"  会话已加密保存: {args.name}（{saved['domain']}，{saved['ttl_days']} 天）")
            print(f"  之后用: dsh-id session use {args.name}")
        raise SystemExit(0)
    print(f"✗ 没确认登录成功（{reason}）——看截图定位卡在哪", file=sys.stderr)
    raise SystemExit(6)


if __name__ == "__main__":
    main()
