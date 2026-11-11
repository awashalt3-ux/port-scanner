from __future__ import annotations

import asyncio
import ipaddress

from .base import ModuleResult, ScanContext, Target

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid DNS port {value!r}") from exc
    if not 0 < port <= 65535:
        raise ValueError(f"DNS port out of range: {port}")
    return port


def parse_dns_server(value: str) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError("--dns-server cannot be empty")

    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("malformed IPv6 DNS server")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            port = _parse_port(rest[1:])
        elif rest:
            raise ValueError("--dns-server must be IP or [IPv6]:port")
    elif value.count(":") == 1:
        host, port_text = value.split(":", 1)
        port = _parse_port(port_text)
    else:
        host = value
        port = 53

    if not host:
        raise ValueError("--dns-server must be an IP address")

    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("--dns-server must be an IP address") from exc

    return host, port


class DnsScanModule:
    name = "dns"

    async def run(self, target: Target, context: ScanContext) -> ModuleResult:
        try:
            import dns.asyncresolver
            import dns.exception
            import dns.resolver
            import dns.reversename
        except ImportError:
            return ModuleResult(
                name=self.name,
                ok=False,
                error="dnspython is required for the dns module",
            )

        if context.dns_server is None:
            server, port = "", 53
        else:
            try:
                server, port = parse_dns_server(context.dns_server)
            except ValueError as exc:
                return ModuleResult(name=self.name, ok=False, error=str(exc))

        resolver = dns.asyncresolver.Resolver(configure=context.dns_server is None)
        if context.dns_server is not None:
            resolver.nameservers = [server]
            resolver.port = port
        resolver.timeout = context.timeout
        resolver.lifetime = context.timeout
        resolver.search = []

        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}

        async def resolve_type(
            record_type: str,
        ) -> tuple[str, list[str] | None, str | None]:
            try:
                answer = await resolver.resolve(target.host, record_type, lifetime=context.timeout)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return record_type, None, None
            except dns.resolver.NoNameservers as exc:
                return record_type, None, f"no nameservers: {exc}"
            except dns.exception.Timeout:
                return record_type, None, "timeout"
            except dns.exception.DNSException as exc:
                return record_type, None, type(exc).__name__
            return record_type, [item.to_text() for item in answer], None

        for record_type, values, error in await asyncio.gather(
            *(resolve_type(record_type) for record_type in RECORD_TYPES)
        ):
            if error is not None:
                errors[record_type] = error
            elif values is not None:
                records[record_type] = values

        ptr_values: list[str] = []
        ptr_addresses = (*records.get("A", []), *records.get("AAAA", []))
        if ptr_addresses:

            async def resolve_ptr(
                address: str,
            ) -> tuple[str, list[str] | None, str | None]:
                try:
                    reverse = dns.reversename.from_address(address)
                    answer = await resolver.resolve(reverse, "PTR", lifetime=context.timeout)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return address, None, None
                except dns.exception.Timeout:
                    return address, None, "timeout"
                except dns.exception.DNSException as exc:
                    return address, None, type(exc).__name__
                return address, [item.to_text() for item in answer], None

            ptr_error: str | None = None
            for _, values, error in await asyncio.gather(
                *(resolve_ptr(address) for address in ptr_addresses)
            ):
                if error is not None and ptr_error is None:
                    ptr_error = error
                elif values:
                    ptr_values.extend(values)

            if ptr_error is not None:
                errors["PTR"] = ptr_error

        if ptr_values:
            records["PTR"] = list(dict.fromkeys(ptr_values))

        summary = ", ".join(records) if records else "no records"
        if errors:
            summary += f" ({len(errors)} error{'s' if len(errors) != 1 else ''})"

        return ModuleResult(
            name=self.name,
            ok=not errors,
            summary=summary,
            data={"records": records, "errors": errors},
        )
