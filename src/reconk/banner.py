"""ASCII banner for Reconk CLI."""

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
      v{version} — by nkbeast
"""

TAGLINE = "End-to-end bug bounty reconnaissance. Network · DNS · Subdomains · JS · Params · Tech."


def get_banner(version: str) -> str:
    return BANNER.format(version=version)
