"""Router integrations. ROUTER_TYPE picks the driver."""
from .base import RouterBase, RouterError
from .opnsense import OpnsenseRouter
from .openwrt import OpenwrtRouter
from .pfsense import PfsenseRouter
from .unifi import UnifiRouter

DRIVERS = {
    "opnsense": OpnsenseRouter,
    "pfsense": PfsenseRouter,
    "unifi": UnifiRouter,
    "openwrt": OpenwrtRouter,
}


class NoRouter(RouterBase):
    """Placeholder when no router is configured."""
    brand = "Router"
    needs = ("_never",)
    _never = None


def create_router(cfg):
    kind = (cfg.router_type or "").lower()
    if kind == "linksys":
        from ..router_linksys import LinksysRouter
        return LinksysRouter(cfg)
    if kind in DRIVERS:
        return DRIVERS[kind](cfg)
    return NoRouter(cfg)


__all__ = ["create_router", "RouterError", "RouterBase", "DRIVERS"]
