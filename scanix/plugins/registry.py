"""Original reviewed builtins. Entries cannot select arbitrary code or destinations."""
from dataclasses import asdict, dataclass

API_VERSION = 1
REGISTRY_VERSION = '1.0.0'


@dataclass(frozen=True)
class Plugin:
    id: str
    protocol: str
    transport: str
    capabilities: tuple[str, ...]
    intrusive: bool = False
    connections: int = 1
    transmissions: int = 2
    response_bytes: int = 4096


PLUGINS = {p.id: p for p in (
    Plugin('http.info.v1', 'http', 'tcp', ('connect', 'http_head')),
    Plugin('tls.info.v1', 'tls', 'tcp', ('connect', 'tls_handshake')),
    Plugin('ssh.info.v1', 'ssh', 'tcp', ('connect', 'passive_greeting')),
    Plugin('dns.info.v1', 'dns', 'udp', ('connect', 'dns_minimal_query')),
)}


def select(value):
    names = value.split(',') if isinstance(value, str) else value
    aliases = {p.protocol: p.id for p in PLUGINS.values()}
    ids = tuple(dict.fromkeys(aliases.get(name, name) for name in names))
    if len(ids) > 4 or any(name not in PLUGINS for name in ids):
        raise ValueError('select at most four builtin plugins: http,tls,ssh,dns')
    return ids


def permitted(plugin, config):
    return not plugin.intrusive or config.allow_intrusive_plugins


def policy(config):
    return {'enabled': bool(config.plugins), 'api_version': API_VERSION,
            'registry_version': REGISTRY_VERSION, 'plugins': [asdict(PLUGINS[id]) for id in config.plugins],
            'workers': min(config.service_workers, config.concurrency, config.per_host),
            'per_plugin_seconds': config.plugin_timeout,
            'per_endpoint_seconds': 3 if config.service_profile == 'quick' else 8,
            'allow_intrusive': config.allow_intrusive_plugins,
            'allow_excluded_ports': config.allow_excluded_probes,
            'isolation': 'trusted subprocess, same OS privileges; not a sandbox',
            'rate_units': 'shared tokens for connection starts, application writes and TLS handshake starts'}
