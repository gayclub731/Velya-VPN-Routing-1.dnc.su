#!/usr/bin/env python3
"""
Merge Dig + Roscom geoip.dat / geosite.dat for Xray routing.

geoip:
  union of ALL country codes / tags from both sources (CIDR-level dedup)

geosite (only these tags):
  private, ip-check, vpndetect, category-ads, category-ru, whitelist
  - each tag = Dig ∪ Roscom (domain-level dedup)
  - cross-category duplicates removed by priority (most specific wins):
      private > ip-check > vpndetect > category-ads > category-ru > whitelist
"""
from __future__ import annotations

import argparse
import sys
from collections import OrderedDict
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory


# ── Protobuf schema (v2ray/xray geoip + geosite) ──────────────────────────

def _build_pool() -> descriptor_pool.DescriptorPool:
    file_proto = descriptor_pb2.FileDescriptorProto()
    file_proto.name = "geo.proto"
    file_proto.package = "xray.app.router"
    file_proto.syntax = "proto3"

    # CIDR
    cidr = file_proto.message_type.add()
    cidr.name = "CIDR"
    f = cidr.field.add()
    f.name, f.number, f.label, f.type = "ip", 1, 1, 12  # optional bytes
    f = cidr.field.add()
    f.name, f.number, f.label, f.type = "prefix", 2, 1, 13  # optional uint32

    # GeoIP
    geoip = file_proto.message_type.add()
    geoip.name = "GeoIP"
    f = geoip.field.add()
    f.name, f.number, f.label, f.type = "country_code", 1, 1, 9
    f = geoip.field.add()
    f.name, f.number, f.label, f.type, f.type_name = "cidr", 2, 3, 11, ".xray.app.router.CIDR"
    f = geoip.field.add()
    f.name, f.number, f.label, f.type = "reverse_match", 3, 1, 8

    # GeoIPList
    geoip_list = file_proto.message_type.add()
    geoip_list.name = "GeoIPList"
    f = geoip_list.field.add()
    f.name, f.number, f.label, f.type, f.type_name = "entry", 1, 3, 11, ".xray.app.router.GeoIP"

    # Domain.Attribute
    domain = file_proto.message_type.add()
    domain.name = "Domain"
    attr = domain.nested_type.add()
    attr.name = "Attribute"
    f = attr.field.add()
    f.name, f.number, f.label, f.type = "key", 1, 1, 9
    f = attr.field.add()
    f.name, f.number, f.label, f.type = "bool_value", 2, 1, 8
    f = attr.field.add()
    f.name, f.number, f.label, f.type = "int_value", 3, 1, 3
    enum = domain.enum_type.add()
    enum.name = "Type"
    for i, name in enumerate(["Plain", "Regex", "Domain", "Full"]):
        v = enum.value.add()
        v.name, v.number = name, i
    f = domain.field.add()
    f.name, f.number, f.label, f.type, f.type_name = "type", 1, 1, 14, ".xray.app.router.Domain.Type"
    f = domain.field.add()
    f.name, f.number, f.label, f.type = "value", 2, 1, 9
    f = domain.field.add()
    f.name, f.number, f.label, f.type, f.type_name = (
        "attribute", 3, 3, 11, ".xray.app.router.Domain.Attribute"
    )

    # GeoSite
    geosite = file_proto.message_type.add()
    geosite.name = "GeoSite"
    f = geosite.field.add()
    f.name, f.number, f.label, f.type = "country_code", 1, 1, 9
    f = geosite.field.add()
    f.name, f.number, f.label, f.type, f.type_name = "domain", 2, 3, 11, ".xray.app.router.Domain"

    # GeoSiteList
    geosite_list = file_proto.message_type.add()
    geosite_list.name = "GeoSiteList"
    f = geosite_list.field.add()
    f.name, f.number, f.label, f.type, f.type_name = "entry", 1, 3, 11, ".xray.app.router.GeoSite"

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_proto)
    return pool


POOL = _build_pool()


def _msg(name: str):
    desc = POOL.FindMessageTypeByName(f"xray.app.router.{name}")
    if hasattr(message_factory, "GetMessageClass"):
        return message_factory.GetMessageClass(desc)()
    return message_factory.MessageFactory(POOL).GetPrototype(desc)()


def load_geoip(path: Path):
    msg = _msg("GeoIPList")
    msg.ParseFromString(path.read_bytes())
    return msg


def load_geosite(path: Path):
    msg = _msg("GeoSiteList")
    msg.ParseFromString(path.read_bytes())
    return msg


def geoip_summary(msg) -> dict[str, int]:
    return {e.country_code: len(e.cidr) for e in msg.entry}


def geosite_summary(msg) -> dict[str, int]:
    return {e.country_code: len(e.domain) for e in msg.entry}


def _cidr_key(c) -> tuple:
    return (c.ip, c.prefix)


def _domain_key(d) -> tuple:
    """Full key: type + value + attributes (exact rule identity)."""
    attrs = tuple(
        sorted(
            (a.key, getattr(a, "bool_value", False), getattr(a, "int_value", 0))
            for a in d.attribute
        )
    )
    return (int(d.type), d.value, attrs)


def _domain_value_key(d) -> tuple:
    """Match key for cross-category dedup: type + value (ignore attributes)."""
    return (int(d.type), d.value.lower())


def merge_geoip(dig_path: Path, roscom_path: Path):
    dig = load_geoip(dig_path)
    ros = load_geoip(roscom_path)

    by_code: OrderedDict[str, dict] = OrderedDict()

    def ingest(src, label: str):
        for entry in src.entry:
            code = entry.country_code
            if code not in by_code:
                by_code[code] = {
                    "reverse_match": entry.reverse_match,
                    "cidrs": OrderedDict(),
                    "sources": set(),
                }
            bucket = by_code[code]
            bucket["sources"].add(label)
            bucket["reverse_match"] = bucket["reverse_match"] or entry.reverse_match
            for c in entry.cidr:
                bucket["cidrs"][_cidr_key(c)] = c

    ingest(dig, "dig")
    ingest(ros, "roscom")

    out = _msg("GeoIPList")
    stats = []
    for code, bucket in by_code.items():
        e = out.entry.add()
        e.country_code = code
        e.reverse_match = bucket["reverse_match"]
        for c in bucket["cidrs"].values():
            nc = e.cidr.add()
            nc.ip = c.ip
            nc.prefix = c.prefix
        stats.append((code, len(e.cidr), sorted(bucket["sources"])))
    return out, stats


# Geosite tags for Xray routing (order = output order)
# Cross-dedup priority: earlier tags keep a domain; later tags drop it.
GEOSITE_PRIORITY: tuple[str, ...] = (
    "private",
    "ip-check",
    "vpndetect",
    "category-ads",
    "category-ru",
    "whitelist",
)


def _copy_domain(dst_entry, src_domain) -> None:
    nd = dst_entry.domain.add()
    nd.type = src_domain.type
    nd.value = src_domain.value
    for a in src_domain.attribute:
        na = nd.attribute.add()
        na.key = a.key
        if a.bool_value:
            na.bool_value = a.bool_value
        if a.int_value:
            na.int_value = a.int_value


def merge_geosite(
    dig_path: Path,
    roscom_path: Path,
    tags: tuple[str, ...] = GEOSITE_PRIORITY,
    cross_dedup: bool = True,
):
    """
    Build geosite.dat with only requested tags.
    Each tag = Dig ∪ Roscom with within-tag dedup.
    If cross_dedup=True, a domain kept in a higher-priority tag is removed
    from lower-priority tags (no repeated rules across categories).
    """
    dig = load_geosite(dig_path)
    ros = load_geosite(roscom_path)

    dig_map = {e.country_code.lower(): e for e in dig.entry}
    ros_map = {e.country_code.lower(): e for e in ros.entry}

    wanted = [t.lower() for t in tags]

    # 1) Union dig+roscom per tag (within-tag exact dedup)
    merged: OrderedDict[str, dict] = OrderedDict()
    for code_l in wanted:
        domains: OrderedDict = OrderedDict()
        sources: list[str] = []
        display_code = code_l

        for label, src_map in (("dig", dig_map), ("roscom", ros_map)):
            entry = src_map.get(code_l)
            if entry is None:
                continue
            sources.append(label)
            display_code = entry.country_code  # preserve original casing from first hit
            for d in entry.domain:
                domains[_domain_key(d)] = d

        if not sources:
            print(f"WARNING: {code_l} not found in dig or roscom", file=sys.stderr)
            continue

        # Prefer Dig casing if present
        if code_l in dig_map:
            display_code = dig_map[code_l].country_code

        merged[code_l] = {
            "code": display_code,
            "domains": domains,
            "sources": sources,
            "before": len(domains),
        }

    # 2) Cross-category dedup by priority (type + value, case-insensitive value)
    removed_cross: dict[str, int] = {k: 0 for k in merged}
    if cross_dedup:
        claimed: set[tuple] = set()
        for code_l, bucket in merged.items():
            keep: OrderedDict = OrderedDict()
            for key, d in bucket["domains"].items():
                vk = _domain_value_key(d)
                if vk in claimed:
                    removed_cross[code_l] += 1
                    continue
                claimed.add(vk)
                keep[key] = d
            bucket["domains"] = keep

    # 3) Build output
    out = _msg("GeoSiteList")
    stats = []
    for code_l, bucket in merged.items():
        e = out.entry.add()
        e.country_code = bucket["code"]
        for d in bucket["domains"].values():
            _copy_domain(e, d)
        stats.append(
            (
                bucket["code"],
                len(e.domain),
                bucket["sources"],
                bucket["before"],
                removed_cross.get(code_l, 0),
            )
        )
    return out, stats


def main():
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="Merge Dig+Roscom geoip/geosite .dat for Xray")
    ap.add_argument("--dig-geoip", type=Path, default=root / "Dig" / "geoip.dat")
    ap.add_argument("--dig-geosite", type=Path, default=root / "Dig" / "geosite.dat")
    ap.add_argument("--roscom-geoip", type=Path, default=root / "roscom" / "geoip.dat")
    ap.add_argument("--roscom-geosite", type=Path, default=root / "roscom" / "geosite.dat")
    ap.add_argument("--out-dir", type=Path, default=root / "release")
    ap.add_argument("--no-cross-dedup", action="store_true", help="Keep domains in multiple geosite tags")
    ap.add_argument("--inspect-only", action="store_true")
    args = ap.parse_args()

    print("=== Dig geoip ===")
    dig_ip = load_geoip(args.dig_geoip)
    for k, v in sorted(geoip_summary(dig_ip).items(), key=lambda x: x[0].lower()):
        print(f"  {k}: {v} cidrs")

    print("=== Roscom geoip ===")
    ros_ip = load_geoip(args.roscom_geoip)
    for k, v in sorted(geoip_summary(ros_ip).items(), key=lambda x: x[0].lower()):
        print(f"  {k}: {v} cidrs")

    print("=== Dig geosite ===")
    dig_site = load_geosite(args.dig_geosite)
    for k, v in sorted(geosite_summary(dig_site).items(), key=lambda x: x[0].lower()):
        print(f"  {k}: {v} domains")

    print("=== Roscom geosite ===")
    ros_site = load_geosite(args.roscom_geosite)
    for k, v in sorted(geosite_summary(ros_site).items(), key=lambda x: x[0].lower()):
        print(f"  {k}: {v} domains")

    if args.inspect_only:
        return

    args.out_dir.mkdir(parents=True, exist_ok=True)

    geoip_out, geoip_stats = merge_geoip(args.dig_geoip, args.roscom_geoip)
    geoip_path = args.out_dir / "geoip.dat"
    geoip_path.write_bytes(geoip_out.SerializeToString())
    print(f"\n=== Merged geoip → {geoip_path} ({geoip_path.stat().st_size} bytes) ===")
    for code, n, srcs in geoip_stats:
        print(f"  {code}: {n} cidrs  [{'+'.join(srcs)}]")

    geosite_out, geosite_stats = merge_geosite(
        args.dig_geosite,
        args.roscom_geosite,
        cross_dedup=not args.no_cross_dedup,
    )
    geosite_path = args.out_dir / "geosite.dat"
    geosite_path.write_bytes(geosite_out.SerializeToString())
    print(f"\n=== Merged geosite → {geosite_path} ({geosite_path.stat().st_size} bytes) ===")
    print("  priority (keep → drop): " + " > ".join(GEOSITE_PRIORITY))
    for code, n, srcs, before, dropped in geosite_stats:
        extra = f"  (union={before}, cross-dropped={dropped})" if dropped or before != n else ""
        print(f"  {code}: {n} domains  [{'+'.join(srcs)}]{extra}")

    # Verify no internal duplicates and no cross-tag value collisions
    print("\n=== Dedup verification ===")
    site = load_geosite(geosite_path)
    ok = True
    all_values: dict[tuple, str] = {}
    for e in site.entry:
        seen = set()
        for d in e.domain:
            k = _domain_key(d)
            if k in seen:
                print(f"  FAIL internal dup in {e.country_code}: {d.value}")
                ok = False
            seen.add(k)
            vk = _domain_value_key(d)
            if not args.no_cross_dedup:
                if vk in all_values:
                    print(f"  FAIL cross dup {vk} in {e.country_code} and {all_values[vk]}")
                    ok = False
                all_values[vk] = e.country_code
        print(f"  {e.country_code}: {len(e.domain)} domains, unique keys OK")
    if ok:
        print("  All checks passed: no repeated rules.")

    print("\nDone.")


if __name__ == "__main__":
    main()
