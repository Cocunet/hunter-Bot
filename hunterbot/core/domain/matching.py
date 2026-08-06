import ipaddress


def target_matches(scope_target: str, requested_target: str) -> bool:
    """Whether an authorized ``scope_target`` covers ``requested_target``.

    Pure domain logic shared by the storage layer (to filter candidate
    Scopes) and the authorization service (to make the final allow/deny
    decision), so the matching rules live in exactly one place. Supports:

    - exact match, case-insensitive (``example.com`` == ``example.com``)
    - subdomain match (``example.com`` authorizes ``api.example.com``)
    - CIDR containment (``10.0.0.0/24`` authorizes ``10.0.0.17``)

    A malformed CIDR/IP on either side simply fails that check rather than
    raising, since the two values may legitimately be hostnames instead.
    """
    scope_target = scope_target.strip().lower()
    requested_target = requested_target.strip().lower()

    if scope_target == requested_target:
        return True

    if requested_target.endswith(f".{scope_target}"):
        return True

    try:
        network = ipaddress.ip_network(scope_target, strict=False)
        address = ipaddress.ip_address(requested_target)
    except ValueError:
        return False
    return address in network
