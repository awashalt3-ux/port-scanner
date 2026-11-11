from __future__ import annotations

from .base import ModuleResult, ScanContext, Target
from .http import fetch_http

_RULE_FIELDS = frozenset({"allow", "disallow", "crawl-delay"})


def parse_robots(text: str) -> dict[str, list]:
    groups: list[dict[str, list]] = []
    sitemaps: list[str] = []
    current: dict[str, list] | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        field, value = line.split(":", 1)
        field = field.strip().lower()
        value = value.strip()

        if field == "user-agent":
            if current is None or current["rules"]:
                if current is not None:
                    groups.append(current)
                current = {"agents": [], "rules": []}
            if value:
                current["agents"].append(value)
        elif field == "sitemap":
            if value:
                sitemaps.append(value)
        elif field in _RULE_FIELDS and current is not None:
            current["rules"].append({"field": field, "value": value})

    if current is not None:
        groups.append(current)

    return {"groups": groups, "sitemaps": sitemaps}


class RobotsTxtModule:
    name = "robots"

    async def run(self, target: Target, context: ScanContext) -> ModuleResult:
        try:
            response = await fetch_http(
                target.host,
                target.port,
                target.scheme,
                "/robots.txt",
                context.timeout,
            )
        except Exception as exc:
            return ModuleResult(
                name=self.name,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        text = response.body.decode("utf-8", errors="replace").lstrip("\ufeff")
        parsed = parse_robots(text)
        group_count = len(parsed["groups"])
        sitemap_count = len(parsed["sitemaps"])
        summary = (
            f"HTTP {response.status}, {group_count} group"
            f"{'s' if group_count != 1 else ''}, {sitemap_count} sitemap"
            f"{'s' if sitemap_count != 1 else ''}"
        )

        return ModuleResult(
            name=self.name,
            ok=True,
            summary=summary,
            data={
                "status": response.status,
                "reason": response.reason,
                "content_type": response.header("content-type"),
                "body_bytes": len(response.body),
                "groups": parsed["groups"],
                "sitemaps": parsed["sitemaps"],
            },
        )
