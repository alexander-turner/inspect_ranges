"""Gateway election: which router carries each network's default route.

Election follows networking-v0.2 §2: an explicit `gateway:` wins; otherwise the single attached router is elected implicitly. Validation rejects the ambiguous case (`ambiguous-gateway`) before compilation, so this stage never guesses. Networks with no attached router have no gateway and are absent from the result.
"""

from ipaddress import IPv4Address

from ..types import RangeSpec
from ._allocate import Allocation


def elect_gateways(spec: RangeSpec, allocation: Allocation) -> dict[str, IPv4Address]:
    """Return each network's default-gateway address, keyed by network name.

    Args:
        spec: The validated range definition.
        allocation: The range's allocation (supplies the elected router's address on the network).

    Returns:
        Gateway addresses for every network with at least one attached router.
    """
    gateways: dict[str, IPv4Address] = {}
    for network in spec.networks:
        attached = [
            router
            for router in spec.routers
            if any(interface.network == network.name for interface in router.interfaces)
        ]
        if not attached:
            continue
        elected = network.gateway or attached[0].name
        allocated = allocation.guest(elected)
        gateways[network.name] = next(
            interface.ip
            for interface in allocated.interfaces
            if interface.network == network.name
        )
    return gateways
