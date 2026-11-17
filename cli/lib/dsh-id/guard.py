#!/usr/bin/env python3
"""dsh-id guard — 不可逆操作审批（防误删/误付）

用法
----
    dsh-id guard check "<操作描述>"      # AI 执行危险操作前调用
    dsh-id guard pending                 # 列出待批准
    dsh-id guard approve <id>            # 批准
    dsh-id guard reject <id> [--note N]  # 拒绝
    dsh-id guard status <id>             # 查某一项状态
    dsh-id guard rules                   # 查看当前规则

退出码（便于 AI 判断）
----
    check:  0 = allow（可执行）
            10 = require_approval（必须停下等老板）
    其它:   0 = 成功，1 = 失败

设计：简单可用优先。命中危险词就问，不确定就问——宁可多问一次。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/.local/lib"))
import guardlib as G  # noqa: E402

EXIT_ALLOW = 0
EXIT_APPROVAL = 10
EXIT_THROTTLE = 11
EXIT_ERROR = 1


def cmd_check(args):
    action = " ".join(args.action).strip()
    if not action:
        sys.exit("必须提供操作描述")

    r = G.check(action)

    if r["decision"] == "allow":
        reason = "未命中危险规则"
        if r["overrides"]:
            reason = "命中放行词: " + ", ".join(r["overrides"])
        elif r["readonly"]:
            reason = "只读操作"

        rate = G.rate_check(action, scope=getattr(args, "scope", None))
        if rate["decision"] == "throttled":
            print("throttled")
            print(f"  原因:    {rate['reason']}")
            print(f"  规则:    {rate['key']}  {rate['rule']}")
            print(f"  操作:    {action}")
            print()
            print("  ⚠ 先别做。等一会儿、或换账号、或查清失败原因后 dsh-id guard reset")
            G._audit(action="guard_check", cred="-", host="-", path="-", status=11,
                     note="throttled %s: %s" % (rate["key"], rate["reason"]))
            sys.exit(EXIT_THROTTLE)

        if rate["key"]:
            reason += f"；{rate['reason']}"
        print(f"allow — {reason}")
        G._audit(action="guard_check", cred="-", host="-", path="-",
                 status=0, note="allow; action=%s" % action[:120])
        sys.exit(EXIT_ALLOW)

    # require_approval
    print("require_approval")
    print(f"  id:      {r['id']}")
    print(f"  命中词:  {', '.join(r['hits'])}")
    print(f"  操作:    {action}")
    print()
    print("  ⚠ 这是不可逆/高风险操作，必须先获得老板批准。")
    print(f"  请老板执行: dsh-id guard approve {r['id']}")
    print(f"  批准后再继续；被拒绝请放弃该操作。")
    G._audit(action="guard_check", cred="-", host="-", path="-",
             status=10,
             note="require_approval id=%s hits=%s" % (r["id"], ",".join(r["hits"])))
    sys.exit(EXIT_APPROVAL)


def cmd_record(args):
    res = G.record(" ".join(args.action).strip(),
                   ok=not args.fail, scope=args.scope)
    if not res:
        print("（这条不在限速范围，没记）")
        return
    G._audit(action="guard_record", cred="-", host="-", path="-", status=0,
             note=f"{res['key']} ok={not args.fail} count={res['count']} fails={res['fails']}")
    print(f"{res['key']}: 今日 {res['count']} 条，连续失败 {res['fails']} 次")


def cmd_reset(args):
    G.reset(scope=args.scope)
    G._audit(action="guard_reset", cred="-", host="-", path="-", status=0,
             note=f"scope={args.scope or 'all'}")
    print(f"已重置{'（' + args.scope + '）' if args.scope else '全部账号'}的限速与熔断状态")


def cmd_pending(args):
    items = G.pending_items()
    if not items:
        print("（没有待批准的操作）")
        return
    print(f"待批准 {len(items)} 项:")
    print()
    for it in items:
        print(f"  [{it['id']}]  {it['created_at_str']}")
        print(f"        操作: {it['action']}")
        print(f"        命中: {', '.join(it.get('hits') or [])}")
        print()


def cmd_approve(args):
    ok, item, msg = G.decide(args.id, True, who=args.who, note=args.note or "")
    if not ok:
        sys.exit("✗ " + msg)
    print(f"✓ {msg}: [{item['id']}]")
    print(f"  操作: {item['action']}")
    print(f"  批准人: {item.get('decided_by')}  时间: {item.get('decided_at_str')}")
    G._audit(action="guard_approve", cred="-", host="-", path="-", status=0,
             note="id=%s by=%s action=%s" % (item["id"], item.get("decided_by"),
                                             item["action"][:100]))


def cmd_reject(args):
    ok, item, msg = G.decide(args.id, False, who=args.who, note=args.note or "")
    if not ok:
        sys.exit("✗ " + msg)
    print(f"✓ {msg}: [{item['id']}]")
    print(f"  操作: {item['action']}")
    if item.get("note"):
        print(f"  理由: {item['note']}")
    G._audit(action="guard_reject", cred="-", host="-", path="-", status=0,
             note="id=%s by=%s" % (item["id"], item.get("decided_by")))


def cmd_status(args):
    item = G.get_item(args.id)
    if not item:
        sys.exit("✗ 找不到: " + args.id)
    print(f"[{item['id']}] 状态: {item['status']}")
    print(f"  操作: {item['action']}")
    print(f"  提交: {item['created_at_str']}")
    if item.get("decided_at_str"):
        print(f"  处理: {item['decided_at_str']} by {item.get('decided_by')}")
    print()
    print("  " + ("✓ 已批准，可以执行" if item["status"] == "approved"
                  else "✗ 已拒绝，不要执行" if item["status"] == "rejected"
                  else "⏳ 等待老板批准"))
    sys.exit(0 if item["status"] == "approved" else EXIT_APPROVAL
             if item["status"] == "pending" else EXIT_ERROR)


def cmd_rules(args):
    rules = G.load_rate_rules()
    print("限速 / 熔断规则:")
    for k, v in rules.items():
        print(f"  {k}: 每日上限 {v.get('max_per_day')} 条 · 最小间隔 "
              f"{v.get('min_interval_minutes')} 分钟 · 连续失败 {v.get('max_consecutive_failures')} 次熔断")
    print()
    rules = G.load_rules()
    print(f"规则文件: {G.RULES_FILE}")
    print(f"危险词 {len(rules.get('danger') or [])} 个:")
    print("  " + ", ".join(str(x) for x in (rules.get("danger") or [])))
    print()
    ov = rules.get("allow_override") or []
    print(f"放行词 {len(ov)} 个:" + ("  " + ", ".join(map(str, ov)) if ov else " （无）"))


def main():
    ap = argparse.ArgumentParser(
        prog="dsh-id guard", description="不可逆操作审批")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="检查操作是否需要批准（AI 调用）")
    p_check.add_argument("action", nargs="+", help="操作描述")
    p_check.add_argument("--scope", help="账号/对象名，按它分别计数与熔断")
    p_check.set_defaults(func=cmd_check)

    p_rec = sub.add_parser("record", help="记一次实际操作（供上限/间隔/熔断）")
    p_rec.add_argument("action", nargs="+")
    p_rec.add_argument("--scope", help="账号/对象名，按它分别计数")
    p_rec.add_argument("--fail", action="store_true", help="这次失败了（连续失败会计入熔断）")
    p_rec.set_defaults(func=cmd_record)

    p_rst = sub.add_parser("reset", help="重置限速与熔断状态")
    p_rst.add_argument("--scope")
    p_rst.set_defaults(func=cmd_reset)

    p_pending = sub.add_parser("pending", help="列出待批准项")
    p_pending.set_defaults(func=cmd_pending)

    p_app = sub.add_parser("approve", help="批准")
    p_app.add_argument("id")
    p_app.add_argument("--who", default="老板", help="批准人（默认 老板）")
    p_app.add_argument("--note", help="备注")
    p_app.set_defaults(func=cmd_approve)

    p_rej = sub.add_parser("reject", help="拒绝")
    p_rej.add_argument("id")
    p_rej.add_argument("--who", default="老板")
    p_rej.add_argument("--note", help="拒绝理由")
    p_rej.set_defaults(func=cmd_reject)

    p_st = sub.add_parser("status", help="查某一项状态")
    p_st.add_argument("id")
    p_st.set_defaults(func=cmd_status)

    p_rules = sub.add_parser("rules", help="查看当前规则")
    p_rules.set_defaults(func=cmd_rules)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
