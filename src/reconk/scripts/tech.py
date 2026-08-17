#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TechFingerprint  -  Advanced Technology Fingerprinting Tool  (v2.0)
===================================================================

Cross-platform (Windows / Linux / macOS).  Pure-Python: uses async libraries
only, NEVER shells out to external CLI tools (no nmap, whatweb, wafw00f,
httpx-CLI, etc.).  All detection logic is implemented in-process.

What changed in v2.0  (the "1000x" rewrite)
--------------------------------------------
PERFORMANCE
  * ONE shared aiohttp ClientSession + TCPConnector for the WHOLE run
    (previously every probe of every target spun up its own session +
    connector -> dozens of wasted TCP/TLS handshakes per target).
  * DNS results cached on the connector (ttl_dns_cache).
  * Targets are scanned CONCURRENTLY (previously the CLI looped one-by-one).
  * The homepage body is fetched ONCE and reused for every body-based
    fingerprint, source-map check and asset scan (previously re-fetched).
  * Every signature regex is compiled ONCE at import (previously every
    pattern was recompiled on every call to find_patterns()).
  * Optional orjson for fast JSON serialisation.
  * Per-host connection caps + adaptive global semaphore.

DETECTION  ("find ALL the techs / CMS / everything")
  * Wappalyzer-style structured fingerprint database (hundreds of techs across
    25+ categories: web servers, languages, backend & frontend frameworks,
    CMS, e-commerce, JS libraries, UI kits, analytics, tag managers, CDNs,
    WAFs, hosting/PaaS, CRMs, chat widgets, payment, CAPTCHA, fonts, search,
    consent/CMP, error tracking, A/B testing, ...).
  * Multi-signal evidence: HTTP headers, Set-Cookie names, HTML body, inline
    + external <script>, <meta generator>, <link>, response URL, and DNS
    (NS / MX / TXT) records.
  * CONFIDENCE SCORING (0-100) per technology, aggregated across signals.
  * VERSION EXTRACTION via named (?P<version>...) capture groups.
  * IMPLIED technologies (e.g. WooCommerce -> WordPress -> PHP; Next.js ->
    React -> Node.js) with transitive resolution.
  * Category roll-up so you instantly see "what stack is this".
  * Header-value parsing (Server: nginx/1.25.3, X-Powered-By: PHP/8.2.1).
  * Security posture grade computed from response security headers.

Everything else (DNS profiling, TLS inspection, HTTP/2+3, favicon hash,
specific endpoint probes, exposure checks, WebSocket probe, port scan,
JSON/HTML/CSV/TXT output, proxy/header/cookie/auth support) is preserved and
upgraded.

Author: TechFingerprint contributors
License: MIT
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import hashlib
import html as html_lib
import json
import os
import re
import socket
import ssl
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Pattern, Tuple, Set
from urllib.parse import urlparse, urljoin, urlsplit

# ---------------------------------------------------------------------------
# Third-party imports - all pure-Python, cross-platform, pip-installable.
# ---------------------------------------------------------------------------
try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, TCPConnector
    try:
        import brotli  # noqa: F401  (aiohttp auto-uses it for br decoding)
        _HAS_BROTLI = True
    except ImportError:
        _HAS_BROTLI = False
except ImportError:  # pragma: no cover
    print("[!] aiohttp is required:  pip install aiohttp", file=sys.stderr)
    sys.exit(1)

if not _HAS_BROTLI:
    print("[!] 'brotli' package not found but Accept-Encoding advertises 'br'. "
          "Install it (pip install brotli) or br-only servers may fail to decode. "
          "Falling back is handled gracefully, but install is recommended.",
          file=sys.stderr)

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
except ImportError:  # pragma: no cover
    class _N:
        def __getattr__(self, _):
            return ""
    Fore = Back = Style = _N()  # type: ignore

try:
    import mmh3  # MurmurHash3 for Shodan favicon hash
except ImportError:
    mmh3 = None

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    BeautifulSoup = None  # type: ignore
    _HAS_BS4 = False

try:
    import orjson
    _HAS_ORJSON = True
except ImportError:
    _HAS_ORJSON = False


__version__ = "2.0.0"
__prog__ = "tech_fingerprint"


# ===========================================================================
# 1. STRUCTURED FINGERPRINT DATABASE  (Wappalyzer-style)
# ===========================================================================
#
# Each technology maps to a dict with any of these signal keys:
#   cats     : list[str]            -> categories (roll-up grouping)
#   headers  : {header: regex}      -> matched against response headers
#   cookies  : {cookie_name: regex} -> cookie name matched as regex; value optional
#   meta     : {meta_name: regex}   -> matched against <meta name/property content>
#   html     : [regex, ...]         -> matched against raw HTML body
#   script   : [regex, ...]         -> matched against <script src> URLs + inline
#   url      : [regex, ...]         -> matched against final URL / host
#   dns      : {RTYPE: [regex,...]} -> matched against DNS records (TXT/MX/NS/...)
#   implies  : [tech, ...]          -> other techs this one implies
#   excludes : [tech, ...]          -> techs to remove if this one matched
#   cpe      : str                  -> CPE identifier (informational)
#
# A (?P<version>...) named group in ANY regex extracts the version string.
# Confidence is aggregated across signals (see DetectionEngine).

FINGERPRINTS: Dict[str, Dict[str, Any]] = {

    # ---------------- Web servers ----------------------------------------
    "Nginx": {
        "cats": ["Web server"],
        "headers": {"server": r"nginx(?:/(?P<version>[\d.]+))?"},
        "cpe": "cpe:/a:nginx:nginx",
    },
    "Apache HTTP Server": {
        "cats": ["Web server"],
        "headers": {"server": r"(?:^|[^-\w])Apache(?:/(?P<version>[\d.]+))?"},
        "cpe": "cpe:/a:apache:http_server",
    },
    "Apache Tomcat": {
        "cats": ["Web server", "Application server"],
        "headers": {"server": r"Apache-Coyote|Tomcat(?:/(?P<version>[\d.]+))?"},
        "html": [r"Apache Tomcat(?:/(?P<version>[\d.]+))?"],
        "implies": ["Java"],
    },
    "Microsoft IIS": {
        "cats": ["Web server"],
        "headers": {"server": r"(?:Microsoft-)?IIS(?:/(?P<version>[\d.]+))?"},
        "implies": ["Windows Server"],
        "cpe": "cpe:/a:microsoft:iis",
    },
    "LiteSpeed": {
        "cats": ["Web server"],
        "headers": {"server": r"LiteSpeed", "x-litespeed-cache": r""},
    },
    "OpenResty": {
        "cats": ["Web server"],
        "headers": {"server": r"openresty(?:/(?P<version>[\d.]+))?"},
        "implies": ["Nginx", "Lua"],
    },
    "Tengine": {
        "cats": ["Web server"],
        "headers": {"server": r"Tengine(?:/(?P<version>[\d.]+))?"},
        "implies": ["Nginx"],
    },
    "Caddy": {
        "cats": ["Web server"],
        "headers": {"server": r"Caddy"},
    },
    "Lighttpd": {
        "cats": ["Web server"],
        "headers": {"server": r"lighttpd(?:/(?P<version>[\d.]+))?"},
    },
    "Cowboy": {
        "cats": ["Web server"],
        "headers": {"server": r"Cowboy"},
        "implies": ["Erlang"],
    },
    "Jetty": {
        "cats": ["Web server", "Application server"],
        "headers": {"server": r"Jetty(?:\((?P<version>[\d.]+)|/)?"},
        "implies": ["Java"],
    },
    "Gunicorn": {
        "cats": ["Web server"],
        "headers": {"server": r"gunicorn(?:/(?P<version>[\d.]+))?"},
        "implies": ["Python"],
    },
    "Uvicorn": {
        "cats": ["Web server"],
        "headers": {"server": r"uvicorn"},
        "implies": ["Python"],
    },
    "Werkzeug": {
        "cats": ["Web server"],
        "headers": {"server": r"Werkzeug(?:/(?P<version>[\d.]+))?"},
        "implies": ["Python"],
    },
    "Waitress": {
        "cats": ["Web server"],
        "headers": {"server": r"waitress"},
        "implies": ["Python"],
    },
    "Tornado": {
        "cats": ["Web server", "Web framework"],
        "headers": {"server": r"TornadoServer(?:/(?P<version>[\d.]+))?"},
        "implies": ["Python"],
    },
    "Kestrel": {
        "cats": ["Web server"],
        "headers": {"server": r"Kestrel"},
        "implies": ["ASP.NET Core"],
    },
    "Envoy": {
        "cats": ["Web server", "Reverse proxy"],
        "headers": {"server": r"envoy", "x-envoy-upstream-service-time": r""},
    },
    "Traefik": {
        "cats": ["Reverse proxy"],
        "headers": {"server": r"traefik"},
    },
    "HAProxy": {
        "cats": ["Load balancer", "Reverse proxy"],
        "headers": {"server": r"haproxy"},
    },
    "Varnish": {
        "cats": ["Cache server", "Reverse proxy"],
        "headers": {"via": r"varnish", "x-varnish": r"", "x-served-by": r"cache"},
    },
    "Squid": {
        "cats": ["Cache server", "Reverse proxy"],
        "headers": {"via": r"squid(?:/(?P<version>[\d.]+))?", "x-squid-error": r""},
    },
    "IBM HTTP Server": {
        "cats": ["Web server"],
        "headers": {"server": r"IBM_HTTP_Server"},
    },
    "Oracle WebLogic": {
        "cats": ["Application server"],
        "headers": {"server": r"WebLogic"},
        "implies": ["Java"],
    },
    "JBoss / WildFly": {
        "cats": ["Application server"],
        "headers": {"x-powered-by": r"JBoss|WildFly", "server": r"WildFly|JBoss"},
        "implies": ["Java"],
    },
    "Phusion Passenger": {
        "cats": ["Web server"],
        "headers": {"x-powered-by": r"Phusion Passenger(?:[ /](?P<version>[\d.]+))?",
                    "server": r"Phusion Passenger"},
    },
    "Puma": {
        "cats": ["Web server"],
        "headers": {"server": r"Puma"},
        "implies": ["Ruby"],
    },
    "Unicorn": {
        "cats": ["Web server"],
        "headers": {"server": r"Unicorn"},
        "implies": ["Ruby"],
    },

    # ---------------- Programming languages ------------------------------
    "PHP": {
        "cats": ["Programming language"],
        "headers": {"x-powered-by": r"PHP(?:/(?P<version>[\d.]+))?",
                    "server": r"PHP/(?P<version>[\d.]+)",
                    "set-cookie": r"PHPSESSID"},
        "cookies": {"PHPSESSID": r""},
        "url": [r"\.php(?:$|\?)"],
        "cpe": "cpe:/a:php:php",
    },
    "Java": {
        "cats": ["Programming language"],
        "headers": {"x-powered-by": r"Servlet|JSP", "set-cookie": r"JSESSIONID"},
        "cookies": {"JSESSIONID": r""},
        "url": [r"\.jsp(?:$|\?)|\.do(?:$|\?)|\.action(?:$|\?)|\;jsessionid="],
    },
    "Python": {
        "cats": ["Programming language"],
        "headers": {"x-powered-by": r"Python", "server": r"Python/(?P<version>[\d.]+)"},
    },
    "Ruby": {
        "cats": ["Programming language"],
        "headers": {"x-powered-by": r"\bRuby\b", "server": r"\bRuby\b"},
    },
    "Node.js": {
        "cats": ["Programming language", "Runtime"],
        "headers": {"x-powered-by": r"Express|Node\.?js|Next\.js|Nuxt"},
    },
    "Go": {
        "cats": ["Programming language"],
        "headers": {"server": r"(?:^|[\s/])Go(?:lang)?(?:[\s/]|$)|Go-http-client",
                    "x-powered-by": r"(?:^|[\s/])Go(?:lang)?(?:[\s/]|$)"},
    },
    "Erlang": {
        "cats": ["Programming language"],
        "headers": {"server": r"Cowboy|Yaws|MochiWeb"},
    },
    "Lua": {
        "cats": ["Programming language"],
        "headers": {"server": r"openresty"},
    },
    "Perl": {
        "cats": ["Programming language"],
        "headers": {"x-powered-by": r"Perl|mod_perl", "server": r"mod_perl(?:/(?P<version>[\d.]+))?"},
        "url": [r"\.pl(?:$|\?)|\.cgi(?:$|\?)"],
    },
    "Elixir": {
        "cats": ["Programming language"],
        "headers": {"x-powered-by": r"Phoenix"},
    },
    "ColdFusion": {
        "cats": ["Programming language", "Application server"],
        "headers": {"set-cookie": r"CFID|CFTOKEN", "x-powered-by": r"ColdFusion"},
        "cookies": {"CFID": r"", "CFTOKEN": r""},
        "url": [r"\.cfm(?:$|\?)|\.cfc(?:$|\?)"],
    },
    "Windows Server": {
        "cats": ["Operating system"],
        "headers": {"server": r"Microsoft-IIS|Win(?:32|64)"},
    },
    ".NET": {
        "cats": ["Programming language"],
        "headers": {"x-aspnet-version": r"(?P<version>[\d.]+)",
                    "x-powered-by": r"ASP\.NET",
                    "set-cookie": r"ASP\.NET_SessionId|\.AspNet"},
        "cookies": {"ASP.NET_SessionId": r""},
    },
}


FINGERPRINTS.update({
    # ---------------- Backend / web frameworks ---------------------------
    "Django": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"csrftoken|django_language|sessionid"},
        "cookies": {"csrftoken": r"", "django_language": r""},
        "html": [r"__admin_media_prefix__|csrfmiddlewaretoken"],
        "implies": ["Python"],
    },
    "Flask": {
        "cats": ["Web framework"],
        "headers": {"server": r"Werkzeug", "set-cookie": r"session=eyJ"},
        "implies": ["Python"],
    },
    "FastAPI": {
        "cats": ["Web framework"],
        "headers": {"server": r"uvicorn"},
        "html": [r"swagger-ui|/openapi\.json"],
        "implies": ["Python", "Starlette"],
    },
    "Starlette": {
        "cats": ["Web framework"],
        "implies": ["Python"],
    },
    "Tornado (framework)": {
        "cats": ["Web framework"],
        "headers": {"server": r"TornadoServer"},
        "implies": ["Python"],
    },
    "Ruby on Rails": {
        "cats": ["Web framework"],
        "headers": {"x-powered-by": r"Phusion Passenger",
                    "set-cookie": r"_session_id|_rails|request_method"},
        "cookies": {"_session_id": r""},
        "html": [r'csrf-param" content="authenticity_token"|/assets/application-[a-f0-9]{32,}\.(?:js|css)'],
        "implies": ["Ruby"],
    },
    "Sinatra": {
        "cats": ["Web framework"],
        "headers": {"x-powered-by": r"Sinatra", "server": r"WEBrick|thin"},
        "implies": ["Ruby"],
    },
    "Laravel": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"laravel_session|XSRF-TOKEN"},
        "cookies": {"laravel_session": r"", "XSRF-TOKEN": r""},
        "implies": ["PHP"],
    },
    "Symfony": {
        "cats": ["Web framework"],
        "headers": {"x-debug-token": r"", "set-cookie": r"sf_redirect|symfony"},
        "html": [r"/bundles/|sf-toolbar|symfony-profiler"],
        "implies": ["PHP"],
    },
    "CodeIgniter": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"ci_session|ci_csrf_token"},
        "cookies": {"ci_session": r""},
        "implies": ["PHP"],
    },
    "CakePHP": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"CAKEPHP|cakephp"},
        "cookies": {"CAKEPHP": r""},
        "implies": ["PHP"],
    },
    "Yii": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"YII_CSRF_TOKEN|_identity"},
        "html": [r"yii\.(?:js|gridView|activeForm)"],
        "implies": ["PHP"],
    },
    "Zend / Laminas": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"ZDEDebuggerPresent|zf_"},
        "implies": ["PHP"],
    },
    "Express": {
        "cats": ["Web framework"],
        "headers": {"x-powered-by": r"Express"},
        "implies": ["Node.js"],
    },
    "Koa": {
        "cats": ["Web framework"],
        "headers": {"x-powered-by": r"Koa"},
        "implies": ["Node.js"],
    },
    "NestJS": {
        "cats": ["Web framework"],
        "html": [r"nestjs"],
        "implies": ["Node.js"],
    },
    "Hapi": {
        "cats": ["Web framework"],
        "headers": {"server": r"hapi"},
        "implies": ["Node.js"],
    },
    "Spring": {
        "cats": ["Web framework"],
        "headers": {"x-application-context": r"", "set-cookie": r"JSESSIONID"},
        "html": [r"org\.springframework|Whitelabel Error Page"],
        "implies": ["Java"],
    },
    "Spring Boot": {
        "cats": ["Web framework"],
        "headers": {"x-application-context": r""},
        "html": [r"Whitelabel Error Page"],
        "implies": ["Spring", "Java"],
    },
    "ASP.NET": {
        "cats": ["Web framework"],
        "headers": {"x-aspnet-version": r"(?P<version>[\d.]+)",
                    "x-powered-by": r"ASP\.NET",
                    "set-cookie": r"ASP\.NET_SessionId"},
        "html": [r"__VIEWSTATE|__EVENTVALIDATION|aspnetForm"],
        "implies": [".NET", "Microsoft IIS"],
    },
    "ASP.NET Core": {
        "cats": ["Web framework"],
        "headers": {"x-powered-by": r"ASP\.NET", "server": r"Kestrel"},
        "implies": [".NET"],
    },
    "ASP.NET MVC": {
        "cats": ["Web framework"],
        "headers": {"x-aspnetmvc-version": r"(?P<version>[\d.]+)"},
        "implies": ["ASP.NET"],
    },
    "Phoenix Framework": {
        "cats": ["Web framework"],
        "headers": {"set-cookie": r"_.*_key=", "x-powered-by": r"Phoenix"},
        "html": [r"phoenix\.(?:js)|data-phx-"],
        "implies": ["Elixir"],
    },
    "Gin": {
        "cats": ["Web framework"],
        "implies": ["Go"],
    },
    "Echo (Go)": {
        "cats": ["Web framework"],
        "implies": ["Go"],
    },
    "Fiber (Go)": {
        "cats": ["Web framework"],
        "headers": {"x-powered-by": r"Fiber"},
        "implies": ["Go"],
    },
    "Strapi": {
        "cats": ["CMS", "Web framework"],
        "headers": {"x-powered-by": r"Strapi"},
        "implies": ["Node.js"],
    },

    # ---------------- Frontend frameworks / libraries --------------------
    "React": {
        "cats": ["JavaScript framework"],
        "html": [r"data-reactroot|data-reactid|react(?:-dom)?(?:\.production|\.development)?\.min\.js"],
        "script": [r"/react(?:-dom)?[.@-][\d.]*\.?(?:production\.)?min\.js", r"react@(?P<version>[\d.]+)"],
    },
    "Vue.js": {
        "cats": ["JavaScript framework"],
        "html": [r"data-v-[0-9a-f]{8}|__vue__|v-cloak|window\.__VUE"],
        "script": [r"/vue(?:@(?P<version>[\d.]+))?(?:\.runtime)?(?:\.min)?\.js"],
    },
    "Angular": {
        "cats": ["JavaScript framework"],
        "html": [r"ng-version=\"(?P<version>[\d.]+)\"|_ngcontent-|_nghost-|ng-app"],
        "script": [r"/(?:@angular|angular)[.@/-][\d.]*"],
    },
    "AngularJS": {
        "cats": ["JavaScript framework"],
        "html": [r"ng-app|ng-controller|ng-repeat|angular\.module"],
        "script": [r"angular(?:\.min)?\.js"],
    },
    "Svelte": {
        "cats": ["JavaScript framework"],
        "html": [r"svelte-[0-9a-z]{4,}|class=\"svelte-"],
    },
    "SvelteKit": {
        "cats": ["JavaScript framework"],
        "html": [r"__sveltekit_|data-sveltekit"],
        "implies": ["Svelte"],
    },
    "Preact": {
        "cats": ["JavaScript framework"],
        "script": [r"/preact(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "SolidJS": {
        "cats": ["JavaScript framework"],
        "html": [r"_\$HY|solid-js"],
    },
    "Qwik": {
        "cats": ["JavaScript framework"],
        "html": [r"q:container|qwikloader|q:base"],
    },
    "Ember.js": {
        "cats": ["JavaScript framework"],
        "html": [r"ember-view|id=\"ember\d+\"|ember\.(?:debug|prod)?\.?js"],
    },
    "Backbone.js": {
        "cats": ["JavaScript framework"],
        "script": [r"backbone(?:-min)?\.js", r"backbone@(?P<version>[\d.]+)"],
    },
    "Alpine.js": {
        "cats": ["JavaScript framework"],
        "html": [r"x-data=|x-bind:|@click=\"|alpine(?:js)?(?:@(?P<version>[\d.]+))?"],
    },
    "htmx": {
        "cats": ["JavaScript framework"],
        "html": [r"hx-(?:get|post|trigger|swap|target)="],
        "script": [r"htmx(?:\.org)?(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "Stimulus": {
        "cats": ["JavaScript framework"],
        "html": [r"data-controller=|stimulus"],
    },
    "Turbo / Hotwire": {
        "cats": ["JavaScript framework"],
        "html": [r"turbo-frame|turbo-stream|data-turbo"],
    },
    "Lit": {
        "cats": ["JavaScript framework"],
        "script": [r"/lit(?:-element|-html)?(?:@(?P<version>[\d.]+))?"],
    },
    "Meteor": {
        "cats": ["JavaScript framework"],
        "html": [r"__meteor_runtime_config__|Meteor\.startup"],
    },
    "Mithril": {
        "cats": ["JavaScript framework"],
        "script": [r"mithril(?:\.min)?\.js"],
    },

    # ---------------- Meta-frameworks / SSG ------------------------------
    "Next.js": {
        "cats": ["Web framework", "Static site generator"],
        "headers": {"x-powered-by": r"Next\.js(?:[ /](?P<version>[\d.]+))?"},
        "html": [r"__NEXT_DATA__|/_next/static/"],
        "implies": ["React", "Node.js"],
    },
    "Nuxt.js": {
        "cats": ["Web framework", "Static site generator"],
        "html": [r"window\.__NUXT__|/_nuxt/|__nuxt"],
        "implies": ["Vue.js", "Node.js"],
    },
    "Gatsby": {
        "cats": ["Static site generator"],
        "html": [r"___gatsby|/page-data/|gatsby-"],
        "implies": ["React"],
    },
    "Remix": {
        "cats": ["Web framework"],
        "html": [r"__remixContext|__remixManifest|window\.__remix"],
        "implies": ["React", "Node.js"],
    },
    "Astro": {
        "cats": ["Static site generator"],
        "html": [r"astro-island|astro-root|data-astro-"],
        "headers": {"x-powered-by": r"Astro"},
    },
    "Hugo": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Hugo(?:[ /](?P<version>[\d.]+))?"},
    },
    "Jekyll": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Jekyll(?:[ /]v?(?P<version>[\d.]+))?"},
    },
    "Hexo": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Hexo(?:[ /](?P<version>[\d.]+))?"},
    },
    "Eleventy": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Eleventy(?:[ /]v?(?P<version>[\d.]+))?"},
    },
    "Docusaurus": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Docusaurus(?:[ /]v?(?P<version>[\d.]+))?"},
        "implies": ["React"],
    },
    "VuePress": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"VuePress(?:[ /](?P<version>[\d.]+))?"},
        "implies": ["Vue.js"],
    },
    "Gridsome": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Gridsome(?:[ /](?P<version>[\d.]+))?"},
        "implies": ["Vue.js"],
    },

    # ---------------- Build tools / bundlers -----------------------------
    "Webpack": {
        "cats": ["Build tool"],
        "html": [r"webpackJsonp|__webpack_require__|webpackChunk"],
    },
    "Vite": {
        "cats": ["Build tool"],
        "html": [r"/@vite/client|vite/dist|type=\"module\"[^>]+/assets/index-[\w-]+\.js"],
    },
    "Parcel": {
        "cats": ["Build tool"],
        "html": [r"parcelRequire"],
    },
    "Turbopack": {
        "cats": ["Build tool"],
        "html": [r"turbopack"],
    },
})


FINGERPRINTS.update({
    # ---------------- CMS -------------------------------------------------
    "WordPress": {
        "cats": ["CMS", "Blog"],
        "meta": {"generator": r"WordPress(?:[ /](?P<version>[\d.]+))?"},
        "html": [r"/wp-content/|/wp-includes/|wp-json|wp-embed\.min\.js"],
        "headers": {"link": r"wp-json", "x-pingback": r"xmlrpc\.php"},
        "implies": ["PHP", "MySQL"],
        "cpe": "cpe:/a:wordpress:wordpress",
    },
    "Drupal": {
        "cats": ["CMS"],
        "meta": {"generator": r"Drupal(?:[ /](?P<version>[\d.]+))?"},
        "headers": {"x-generator": r"Drupal(?:[ /](?P<version>[\d.]+))?",
                    "x-drupal-cache": r"", "x-drupal-dynamic-cache": r""},
        "html": [r"/sites/default/files/|drupal\.settings|Drupal\.behaviors|/core/misc/drupal\.js"],
        "implies": ["PHP"],
    },
    "Joomla": {
        "cats": ["CMS"],
        "meta": {"generator": r"Joomla!?(?:[ /-]*(?P<version>[\d.]+))?"},
        "html": [r"/media/jui/|/components/com_|option=com_|Joomla!"],
        "implies": ["PHP"],
    },
    "Ghost": {
        "cats": ["CMS", "Blog"],
        "meta": {"generator": r"Ghost(?:[ /](?P<version>[\d.]+))?"},
        "html": [r"/ghost/|ghost-url|content=\"Ghost"],
        "headers": {"x-powered-by": r"Express"},
        "implies": ["Node.js"],
    },
    "TYPO3": {
        "cats": ["CMS"],
        "meta": {"generator": r"TYPO3(?:[ /](?P<version>[\d.]+))?"},
        "html": [r"/typo3conf/|/typo3temp/|typo3/"],
        "implies": ["PHP"],
    },
    "Craft CMS": {
        "cats": ["CMS"],
        "headers": {"x-powered-by": r"Craft CMS"},
        "html": [r"/cpresources/|Craft CMS"],
        "implies": ["PHP", "Yii"],
    },
    "Concrete CMS": {
        "cats": ["CMS"],
        "meta": {"generator": r"concrete5(?:[ /](?P<version>[\d.]+))?|Concrete CMS"},
        "html": [r"/concrete/|ccm_token"],
        "implies": ["PHP"],
    },
    "Sitecore": {
        "cats": ["CMS"],
        "html": [r"/sitecore/|sc_mode|Sitecore\."],
        "implies": ["ASP.NET"],
    },
    "Adobe Experience Manager": {
        "cats": ["CMS"],
        "html": [r"/etc/designs/|/etc/clientlibs/|/content/dam/|cq:|granite"],
        "implies": ["Java"],
    },
    "Umbraco": {
        "cats": ["CMS"],
        "html": [r"/umbraco/|umbraco_member"],
        "headers": {"x-umbraco-version": r"(?P<version>[\d.]+)"},
        "implies": ["ASP.NET"],
    },
    "Kentico": {
        "cats": ["CMS"],
        "html": [r"CMSPagePlaceholder|/CMSPages/|Kentico"],
        "headers": {"x-kentico-version": r"(?P<version>[\d.]+)"},
        "implies": ["ASP.NET"],
    },
    "DotNetNuke": {
        "cats": ["CMS"],
        "html": [r"/DesktopModules/|DotNetNuke|dnn_"],
        "headers": {"dnnoutputcache": r""},
        "implies": ["ASP.NET"],
    },
    "MODX": {
        "cats": ["CMS"],
        "meta": {"generator": r"MODX(?:[ /](?P<version>[\d.]+))?"},
        "headers": {"x-powered-by": r"MODX"},
        "implies": ["PHP"],
    },
    "Grav": {
        "cats": ["CMS"],
        "headers": {"x-powered-by": r"Grav"},
        "implies": ["PHP"],
    },
    "October CMS": {
        "cats": ["CMS"],
        "html": [r"/modules/system/assets/|cms_flash"],
        "implies": ["PHP", "Laravel"],
    },
    "Statamic": {
        "cats": ["CMS"],
        "headers": {"x-powered-by": r"Statamic"},
        "implies": ["PHP", "Laravel"],
    },
    "ExpressionEngine": {
        "cats": ["CMS"],
        "headers": {"set-cookie": r"exp_csrf_token|exp_sessionid"},
        "implies": ["PHP"],
    },
    "Sitefinity": {
        "cats": ["CMS"],
        "html": [r"Telerik\.Sitefinity|/Telerik\."],
        "implies": ["ASP.NET"],
    },
    "Bitrix": {
        "cats": ["CMS", "E-commerce"],
        "headers": {"set-cookie": r"BITRIX_|PHPSESSID", "x-powered-cms": r"Bitrix"},
        "html": [r"/bitrix/|bx-"],
        "implies": ["PHP"],
    },
    "Contentful": {
        "cats": ["CMS", "Headless CMS"],
        "html": [r"images\.ctfassets\.net|cdn\.contentful\.com"],
    },
    "Sanity": {
        "cats": ["CMS", "Headless CMS"],
        "html": [r"cdn\.sanity\.io|apicdn\.sanity\.io"],
    },
    "Storyblok": {
        "cats": ["CMS", "Headless CMS"],
        "html": [r"a\.storyblok\.com|api\.storyblok\.com"],
    },
    "Prismic": {
        "cats": ["CMS", "Headless CMS"],
        "html": [r"prismic\.io|cdn\.prismic\.io"],
    },
    "Blogger": {
        "cats": ["Blog"],
        "meta": {"generator": r"blogger"},
        "html": [r"\.blogspot\.com|blogger\.com"],
    },
    "HubSpot CMS": {
        "cats": ["CMS"],
        "html": [r"hs-scripts\.com|hubspot\.com/cos/|hsforms\.(?:net|com)|hs-analytics"],
        "headers": {"x-hs-cache-config": r""},
    },

    # ---------------- E-commerce -----------------------------------------
    "Shopify": {
        "cats": ["E-commerce"],
        "headers": {"x-shopify-stage": r"", "x-shopid": r"", "x-sorting-hat-shopid": r""},
        "html": [r"cdn\.shopify\.com|Shopify\.theme|/s/files/|myshopify\.com"],
    },
    "WooCommerce": {
        "cats": ["E-commerce"],
        "meta": {"generator": r"WooCommerce(?:[ /](?P<version>[\d.]+))?"},
        "html": [r"/plugins/woocommerce/|woocommerce-|wc-block|add-to-cart"],
        "implies": ["WordPress", "PHP"],
    },
    "Magento": {
        "cats": ["E-commerce"],
        "html": [r"/skin/frontend/|Mage\.Cookies|/static/version\d+/|mage/cookies|Magento_"],
        "headers": {"set-cookie": r"frontend=|X-Magento"},
        "implies": ["PHP"],
    },
    "BigCommerce": {
        "cats": ["E-commerce"],
        "headers": {"x-bc-": r"", "set-cookie": r"SHOP_SESSION_TOKEN"},
        "html": [r"cdn\d*\.bigcommerce\.com|/stencil/"],
    },
    "PrestaShop": {
        "cats": ["E-commerce"],
        "meta": {"generator": r"PrestaShop"},
        "html": [r"/themes/.*?/assets|prestashop|/modules/ps_"],
        "headers": {"set-cookie": r"PrestaShop-"},
        "implies": ["PHP"],
    },
    "OpenCart": {
        "cats": ["E-commerce"],
        "html": [r"index\.php\?route=|catalog/view/theme|OpenCart"],
        "implies": ["PHP"],
    },
    "Salesforce Commerce Cloud": {
        "cats": ["E-commerce"],
        "html": [r"demandware\.(?:static|edgesuite)|/on/demandware\.store/|dwfrm_"],
    },
    "Wix": {
        "cats": ["CMS", "Website builder"],
        "headers": {"x-wix-request-id": r"", "server": r"Pepyaka"},
        "html": [r"static\.wixstatic\.com|wix\.com|X-Wix"],
    },
    "Squarespace": {
        "cats": ["CMS", "Website builder"],
        "html": [r"static1\.squarespace\.com|squarespace\.com|Squarespace\.afterBodyLoad"],
        "headers": {"server": r"Squarespace"},
    },
    "Webflow": {
        "cats": ["CMS", "Website builder"],
        "meta": {"generator": r"Webflow"},
        "html": [r"assets-global\.website-files\.com|webflow\.js|w-mod-"],
    },
    "Ecwid": {
        "cats": ["E-commerce"],
        "html": [r"app\.ecwid\.com|ecwid_script"],
    },
    "Snipcart": {
        "cats": ["E-commerce"],
        "html": [r"cdn\.snipcart\.com|snipcart"],
    },
    "Shopware": {
        "cats": ["E-commerce"],
        "html": [r"/bundles/shopware|shopware\.min\.js|window\.themeJsPublicPath|data-shopware"],
        "headers": {"x-shopware-cache-id": r""},
        "implies": ["PHP"],
    },
    "Tilda": {
        "cats": ["Website builder"],
        "html": [r"tilda(?:cdn|sites)\.com|t-records"],
    },
    "GoDaddy Website Builder": {
        "cats": ["Website builder"],
        "html": [r"img\d?\.wsimg\.com"],
    },
})


FINGERPRINTS.update({
    # ---------------- JS libraries ---------------------------------------
    "jQuery": {
        "cats": ["JavaScript library"],
        "script": [r"jquery(?:-(?P<version>[\d.]+))?(?:\.slim)?(?:\.min)?\.js",
                   r"jquery@(?P<version>[\d.]+)"],
        "html": [r"jQuery\.fn\.jquery|jquery\.js"],
    },
    "jQuery UI": {
        "cats": ["JavaScript library"],
        "script": [r"jquery-ui(?:-(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "implies": ["jQuery"],
    },
    "jQuery Migrate": {
        "cats": ["JavaScript library"],
        "script": [r"jquery-migrate(?:-(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "implies": ["jQuery"],
    },
    "Lodash": {
        "cats": ["JavaScript library"],
        "script": [r"lodash(?:\.min)?\.js", r"lodash@(?P<version>[\d.]+)"],
    },
    "Underscore.js": {
        "cats": ["JavaScript library"],
        "script": [r"underscore(?:-min|\.min)?\.js", r"underscore@(?P<version>[\d.]+)"],
    },
    "Moment.js": {
        "cats": ["JavaScript library"],
        "script": [r"moment(?:\.min)?\.js", r"moment@(?P<version>[\d.]+)"],
    },
    "Day.js": {
        "cats": ["JavaScript library"],
        "script": [r"dayjs(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "Axios": {
        "cats": ["JavaScript library"],
        "script": [r"axios(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "D3.js": {
        "cats": ["JavaScript library", "Data visualization"],
        "script": [r"d3(?:\.v\d+)?(?:\.min)?\.js", r"d3@(?P<version>[\d.]+)"],
    },
    "Three.js": {
        "cats": ["JavaScript library", "3D"],
        "script": [r"three(?:\.module)?(?:\.min)?\.js", r"three@(?P<version>[\d.]+)"],
        "html": [r"THREE\.(?:Scene|WebGLRenderer|REVISION)"],
    },
    "Chart.js": {
        "cats": ["JavaScript library", "Data visualization"],
        "script": [r"chart(?:\.umd)?(?:\.min)?\.js", r"chart\.js@(?P<version>[\d.]+)"],
    },
    "Highcharts": {
        "cats": ["JavaScript library", "Data visualization"],
        "script": [r"highcharts(?:\.min)?\.js"],
    },
    "ECharts": {
        "cats": ["JavaScript library", "Data visualization"],
        "script": [r"echarts(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "GSAP": {
        "cats": ["JavaScript library", "Animation"],
        "script": [r"gsap(?:@(?P<version>[\d.]+))?(?:\.min)?\.js|TweenMax|TweenLite"],
    },
    "Swiper": {
        "cats": ["JavaScript library", "Carousel"],
        "script": [r"swiper(?:-bundle)?(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"swiper-container|swiper-slide"],
    },
    "Slick Carousel": {
        "cats": ["JavaScript library", "Carousel"],
        "script": [r"slick(?:\.min)?\.js"],
        "html": [r"slick-slider|slick-track"],
    },
    "Owl Carousel": {
        "cats": ["JavaScript library", "Carousel"],
        "script": [r"owl\.carousel(?:\.min)?\.js"],
        "html": [r"owl-carousel"],
    },
    "Leaflet": {
        "cats": ["JavaScript library", "Maps"],
        "script": [r"leaflet(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"leaflet-container|L\.map\("],
    },
    "Mapbox GL JS": {
        "cats": ["JavaScript library", "Maps"],
        "script": [r"mapbox-gl(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"mapboxgl\.|api\.mapbox\.com"],
    },
    "Google Maps": {
        "cats": ["Maps"],
        "script": [r"maps\.googleapis\.com/maps/api"],
    },
    "Video.js": {
        "cats": ["JavaScript library", "Media player"],
        "script": [r"video(?:js)?(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"video-js|vjs-"],
    },
    "Plyr": {
        "cats": ["JavaScript library", "Media player"],
        "script": [r"plyr(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "Hls.js": {
        "cats": ["JavaScript library", "Media player"],
        "script": [r"hls(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "Socket.IO": {
        "cats": ["JavaScript library", "Realtime"],
        "script": [r"socket\.io(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"io\.connect\(|/socket\.io/"],
    },
    "Pusher": {
        "cats": ["Realtime"],
        "script": [r"js\.pusher\.com|pusher(?:\.min)?\.js"],
    },
    "Handlebars": {
        "cats": ["JavaScript library", "Templating"],
        "script": [r"handlebars(?:\.runtime)?(?:\.min)?\.js", r"handlebars@(?P<version>[\d.]+)"],
    },
    "Mustache.js": {
        "cats": ["JavaScript library", "Templating"],
        "script": [r"mustache(?:\.min)?\.js"],
    },
    "Modernizr": {
        "cats": ["JavaScript library"],
        "script": [r"modernizr(?:-(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"js modernizr|class=\"[^\"]*\bno-js\b"],
    },
    "Popper.js": {
        "cats": ["JavaScript library"],
        "script": [r"popper(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "Select2": {
        "cats": ["JavaScript library"],
        "script": [r"select2(?:\.full)?(?:\.min)?\.js"],
        "implies": ["jQuery"],
    },
    "RequireJS": {
        "cats": ["JavaScript library"],
        "script": [r"require(?:\.min)?\.js"],
        "html": [r"data-main=|require\.config\("],
    },
    "core-js": {
        "cats": ["JavaScript library"],
        "script": [r"core-js(?:@(?P<version>[\d.]+))?"],
    },
    "Redux": {
        "cats": ["JavaScript library"],
        "html": [r"__REDUX_DEVTOOLS_EXTENSION__|window\.__PRELOADED_STATE__"],
        "implies": ["React"],
    },
    "RxJS": {
        "cats": ["JavaScript library"],
        "script": [r"rxjs(?:@(?P<version>[\d.]+))?(?:\.min|\.umd)?\.js"],
    },
    "Fancybox": {
        "cats": ["JavaScript library"],
        "script": [r"(?:jquery\.)?fancybox(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
    },
    "Lightbox": {
        "cats": ["JavaScript library"],
        "script": [r"lightbox(?:\.min)?\.js"],
    },
    "AOS (Animate On Scroll)": {
        "cats": ["JavaScript library", "Animation"],
        "script": [r"aos(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"data-aos="],
    },

    # ---------------- UI / CSS frameworks --------------------------------
    "Bootstrap": {
        "cats": ["UI framework"],
        "script": [r"bootstrap(?:\.bundle)?(?:@(?P<version>[\d.]+))?(?:\.min)?\.js"],
        "html": [r"bootstrap(?:@[\d.]+)?(?:\.min)?\.css|data-bs-toggle=|data-toggle=\"(?:modal|dropdown|collapse|tab)\""],
    },
    "Tailwind CSS": {
        "cats": ["UI framework"],
        "html": [r"cdn\.tailwindcss\.com|tailwind(?:@[\d.]+)?(?:\.min)?\.css|/tailwind(?:\.config)?\.js"],
    },
    "Foundation": {
        "cats": ["UI framework"],
        "html": [r"foundation(?:\.min)?\.css|foundation(?:\.min)?\.js|class=\"[^\"]*\bzurb\b"],
    },
    "Bulma": {
        "cats": ["UI framework"],
        "html": [r"bulma(?:@[\d.]+)?(?:\.min)?\.css"],
    },
    "Materialize": {
        "cats": ["UI framework"],
        "html": [r"materialize(?:\.min)?\.(?:css|js)"],
    },
    "Material UI (MUI)": {
        "cats": ["UI framework"],
        "html": [r"MuiButton|css-[a-z0-9]+-Mui|jss\d+|MuiTypography"],
        "implies": ["React"],
    },
    "Ant Design": {
        "cats": ["UI framework"],
        "html": [r"\bant-(?:btn|layout|menu|row|col)\b|antd"],
        "implies": ["React"],
    },
    "Chakra UI": {
        "cats": ["UI framework"],
        "html": [r"chakra-|css-[a-z0-9]+ chakra"],
        "implies": ["React"],
    },
    "Semantic UI": {
        "cats": ["UI framework"],
        "html": [r"semantic(?:\.min)?\.css|class=\"ui "],
    },
    "Tachyons": {
        "cats": ["UI framework"],
        "html": [r"tachyons(?:\.min)?\.css"],
    },
    "Font Awesome": {
        "cats": ["Font", "Icon library"],
        "html": [r"font-?awesome(?:[/.](?P<version>[\d.]+))?|fa-(?:solid|regular|brands|fw)\b|\bfas?\b fa-"],
    },
    "Google Font API": {
        "cats": ["Font"],
        "html": [r"fonts\.googleapis\.com|fonts\.gstatic\.com"],
    },
    "Adobe Fonts (Typekit)": {
        "cats": ["Font"],
        "html": [r"use\.typekit\.net|typekit\.com"],
    },
    "Ionicons": {
        "cats": ["Icon library"],
        "html": [r"ionicons(?:@[\d.]+)?(?:\.min)?\.(?:js|css)|<ion-icon\b|unpkg\.com/ionicons"],
    },
    "Material Icons": {
        "cats": ["Icon library"],
        "html": [r"class=\"material-icons|fonts\.googleapis\.com/icon\?family=Material"],
    },
})


FINGERPRINTS.update({
    # ---------------- Analytics ------------------------------------------
    "Google Analytics": {
        "cats": ["Analytics"],
        "html": [r"google-analytics\.com/(?:ga|analytics)\.js|UA-\d{4,}-\d|_gaq\.push|ga\('create'"],
    },
    "Google Analytics 4": {
        "cats": ["Analytics"],
        "html": [r"googletagmanager\.com/gtag/js\?id=G-|gtag\('config',\s*'G-"],
    },
    "Google Tag Manager": {
        "cats": ["Tag manager"],
        "html": [r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+|dataLayer\.push"],
    },
    "Google Ads": {
        "cats": ["Advertising"],
        "html": [r"googleadservices\.com|googlesyndication\.com|AW-\d{4,}"],
    },
    "Meta Pixel": {
        "cats": ["Analytics", "Advertising"],
        "html": [r"connect\.facebook\.net/.*?/fbevents\.js|fbq\('init'|facebook\.com/tr\?"],
    },
    "Hotjar": {
        "cats": ["Analytics"],
        "html": [r"static\.hotjar\.com|hotjar\.com/c/hotjar|_hjSettings|hjid:"],
    },
    "Mixpanel": {
        "cats": ["Analytics"],
        "html": [r"cdn\.mxpnl\.com|mixpanel\.init|api\.mixpanel\.com"],
    },
    "Segment": {
        "cats": ["Analytics", "Tag manager"],
        "html": [r"cdn\.segment\.(?:com|io)|analytics\.load\(|segment\.com/analytics\.js"],
    },
    "Amplitude": {
        "cats": ["Analytics"],
        "html": [r"cdn\.amplitude\.com|amplitude\.getInstance|api\d?\.amplitude\.com"],
    },
    "Heap": {
        "cats": ["Analytics"],
        "html": [r"cdn\.heapanalytics\.com|heap\.load\("],
    },
    "Matomo (Piwik)": {
        "cats": ["Analytics"],
        "html": [r"matomo\.js|piwik\.js|_paq\.push|matomo\.php"],
    },
    "Plausible": {
        "cats": ["Analytics"],
        "html": [r"plausible\.io/js/|data-domain=\"[^\"]+\"\s+src=\"[^\"]*plausible"],
    },
    "Fathom Analytics": {
        "cats": ["Analytics"],
        "html": [r"cdn\.usefathom\.com|fathom\.js"],
    },
    "Adobe Analytics": {
        "cats": ["Analytics"],
        "html": [r"omniture|s_code\.js|AppMeasurement\.js|sc\.omtrdc\.net|2o7\.net"],
    },
    "Yandex Metrika": {
        "cats": ["Analytics"],
        "html": [r"mc\.yandex\.ru/metrika|ym\(\d+,|yandex_metrika"],
    },
    "Baidu Analytics": {
        "cats": ["Analytics"],
        "html": [r"hm\.baidu\.com/hm\.js|_hmt\.push"],
    },
    "Cloudflare Web Analytics": {
        "cats": ["Analytics"],
        "html": [r"static\.cloudflareinsights\.com|beacon\.min\.js.*cf"],
    },
    "New Relic": {
        "cats": ["Analytics", "RUM"],
        "html": [r"js-agent\.newrelic\.com|NREUM|newrelic\.com"],
    },
    "Datadog RUM": {
        "cats": ["RUM"],
        "html": [r"datadoghq-browser-agent|DD_RUM|datadog-rum"],
    },
    "Microsoft Clarity": {
        "cats": ["Analytics"],
        "html": [r"clarity\.ms/tag|clarity\(\"set\""],
    },
    "Quantcast": {
        "cats": ["Analytics", "Advertising"],
        "html": [r"quantserve\.com|quantcast\.com|__qc"],
    },

    # ---------------- Error tracking / monitoring ------------------------
    "Sentry": {
        "cats": ["Error tracking"],
        "html": [r"browser\.sentry-cdn\.com|Sentry\.init|@sentry/browser|sentry\.io"],
    },
    "LogRocket": {
        "cats": ["Error tracking", "RUM"],
        "html": [r"cdn\.logrocket\.(?:io|com)|LogRocket\.init"],
    },
    "Bugsnag": {
        "cats": ["Error tracking"],
        "html": [r"d2wy8f7a9ursnm\.cloudfront\.net/bugsnag|Bugsnag\.start"],
    },
    "Rollbar": {
        "cats": ["Error tracking"],
        "html": [r"cdn\.rollbar\.com|Rollbar\.init|_rollbarConfig"],
    },

    # ---------------- A/B testing ----------------------------------------
    "Optimizely": {
        "cats": ["A/B testing"],
        "html": [r"cdn\.optimizely\.com|optimizely\.com/js"],
    },
    "VWO": {
        "cats": ["A/B testing"],
        "html": [r"dev\.visualwebsiteoptimizer\.com|_vwo_code|/vwo_|wingify"],
    },
    "Google Optimize": {
        "cats": ["A/B testing"],
        "html": [r"googleoptimize\.com/optimize\.js|GTM-[A-Z0-9]+.*optimize"],
    },

    # ---------------- Chat / support widgets -----------------------------
    "Intercom": {
        "cats": ["Live chat", "CRM"],
        "html": [r"widget\.intercom\.io|js\.intercomcdn\.com|window\.Intercom"],
    },
    "Drift": {
        "cats": ["Live chat"],
        "html": [r"js\.driftt\.com|drift\.load|driftt\.com"],
    },
    "Zendesk Chat": {
        "cats": ["Live chat", "Help desk"],
        "html": [r"static\.zdassets\.com|zendesk\.com/embeddable|zEmbed|zopim"],
    },
    "Crisp": {
        "cats": ["Live chat"],
        "html": [r"client\.crisp\.chat|\$crisp"],
    },
    "Tawk.to": {
        "cats": ["Live chat"],
        "html": [r"embed\.tawk\.to|Tawk_API"],
    },
    "LiveChat": {
        "cats": ["Live chat"],
        "html": [r"cdn\.livechatinc\.com|__lc\.license|livechat"],
    },
    "Olark": {
        "cats": ["Live chat"],
        "html": [r"static\.olark\.com|olark\.identify"],
    },
    "Freshchat": {
        "cats": ["Live chat"],
        "html": [r"wchat\.freshchat\.com|fcWidget"],
    },
    "HubSpot": {
        "cats": ["CRM", "Marketing automation"],
        "html": [r"js\.hs-scripts\.com|js\.hsforms\.net|track\.hubspot\.com|_hsq\.push"],
    },
    "Help Scout": {
        "cats": ["Help desk", "Live chat"],
        "html": [r"beacon-v2\.helpscout\.net|Beacon\("],
    },

    # ---------------- Marketing automation / email -----------------------
    "Marketo": {
        "cats": ["Marketing automation"],
        "html": [r"munchkin\.marketo\.net|Munchkin\.init"],
    },
    "Pardot": {
        "cats": ["Marketing automation"],
        "html": [r"pi\.pardot\.com|pardot\.com/pd\.js"],
    },
    "Mailchimp": {
        "cats": ["Marketing automation", "Email"],
        "html": [r"chimpstatic\.com|list-manage\.com|mc\.us\d+\.list-manage"],
    },
    "Klaviyo": {
        "cats": ["Marketing automation", "Email"],
        "html": [r"static\.klaviyo\.com|klaviyo\.js|_learnq"],
    },
    "ActiveCampaign": {
        "cats": ["Marketing automation"],
        "html": [r"prototype\.activehosted\.com|trackcmp\.net"],
    },

    # ---------------- Payment --------------------------------------------
    "Stripe": {
        "cats": ["Payment processor"],
        "html": [r"js\.stripe\.com|Stripe\(\s*['\"]pk_|stripe\.com/v\d"],
    },
    "PayPal": {
        "cats": ["Payment processor"],
        "html": [r"paypalobjects\.com|paypal\.com/sdk/js|www\.paypal\.com/.*?buttons"],
    },
    "Braintree": {
        "cats": ["Payment processor"],
        "html": [r"js\.braintreegateway\.com|braintree\.client"],
    },
    "Square": {
        "cats": ["Payment processor"],
        "html": [r"js\.squareup\.com|squarecdn\.com"],
    },
    "Adyen": {
        "cats": ["Payment processor"],
        "html": [r"checkoutshopper-live\.adyen\.com|adyen\.encrypt"],
    },
    "Razorpay": {
        "cats": ["Payment processor"],
        "html": [r"checkout\.razorpay\.com|Razorpay\("],
    },
    "Klarna": {
        "cats": ["Payment processor"],
        "html": [r"x\.klarnacdn\.net|klarna\.com/.*?lib"],
    },

    # ---------------- CAPTCHA / bot protection ---------------------------
    "reCAPTCHA": {
        "cats": ["CAPTCHA"],
        "html": [r"www\.google\.com/recaptcha|grecaptcha|gstatic\.com/recaptcha"],
    },
    "hCaptcha": {
        "cats": ["CAPTCHA"],
        "html": [r"hcaptcha\.com/1/api\.js|h-captcha"],
    },
    "Cloudflare Turnstile": {
        "cats": ["CAPTCHA"],
        "html": [r"challenges\.cloudflare\.com/turnstile|cf-turnstile"],
    },

    # ---------------- Consent management (CMP) ---------------------------
    "OneTrust": {
        "cats": ["Cookie compliance"],
        "html": [r"cdn\.cookielaw\.org|otSDKStub|onetrust"],
    },
    "Cookiebot": {
        "cats": ["Cookie compliance"],
        "html": [r"consent\.cookiebot\.com|Cookiebot"],
    },
    "Osano": {
        "cats": ["Cookie compliance"],
        "html": [r"cmp\.osano\.com|osano\.com/cm"],
    },
    "Usercentrics": {
        "cats": ["Cookie compliance"],
        "html": [r"app\.usercentrics\.eu|usercentrics"],
    },
    "CookieYes": {
        "cats": ["Cookie compliance"],
        "html": [r"cdn-cookieyes\.com|cookieyes"],
    },
    "TrustArc": {
        "cats": ["Cookie compliance"],
        "html": [r"consent\.trustarc\.com|trustarc"],
    },

    # ---------------- Search / community ---------------------------------
    "Algolia": {
        "cats": ["Search engine"],
        "html": [r"cdn\.jsdelivr\.net/algoliasearch|algolianet\.com|algolia\.com/.*?search"],
    },
    "Elasticsearch (frontend)": {
        "cats": ["Search engine"],
        "html": [r"elasticsearch|/_search\?"],
    },
    "Disqus": {
        "cats": ["Comment system"],
        "html": [r"disqus\.com/embed\.js|disqus_thread|\.disqus\.com"],
    },
    "Gravatar": {
        "cats": ["Avatars"],
        "html": [r"(?:secure|www)\.gravatar\.com/avatar"],
    },
})


FINGERPRINTS.update({
    # ---------------- CDN -------------------------------------------------
    "Cloudflare": {
        "cats": ["CDN", "Reverse proxy"],
        "headers": {"server": r"cloudflare", "cf-ray": r"", "cf-cache-status": r"",
                    "cf-request-id": r""},
        "cookies": {"__cfduid": r"", "__cf_bm": r"", "cf_clearance": r""},
        "dns": {"NS": [r"\.cloudflare\.com$"]},
    },
    "Akamai": {
        "cats": ["CDN"],
        "headers": {"server": r"AkamaiGHost|AkamaiNetStorage", "x-akamai-": r"",
                    "x-akamai-transformed": r""},
        "dns": {"CNAME": [r"\.akamai(?:edge|technologies|hd)?\.net$"]},
    },
    "Amazon CloudFront": {
        "cats": ["CDN"],
        "headers": {"x-amz-cf-id": r"", "x-amz-cf-pop": r"", "via": r"CloudFront",
                    "server": r"CloudFront"},
        "dns": {"CNAME": [r"\.cloudfront\.net$"]},
        "implies": ["Amazon Web Services"],
    },
    "Fastly": {
        "cats": ["CDN"],
        "headers": {"x-served-by": r"cache-.*?\b", "x-fastly-": r"",
                    "fastly-debug-digest": r"", "x-timer": r""},
        "dns": {"CNAME": [r"\.fastly\.net$|fastlylb\.net$"]},
    },
    "Azure CDN / Front Door": {
        "cats": ["CDN"],
        "headers": {"x-azure-ref": r"", "x-cache": r"TCP_.*?\bazure|x-msedge-ref"},
        "dns": {"CNAME": [r"\.azureedge\.net$|\.azurefd\.net$"]},
        "implies": ["Microsoft Azure"],
    },
    "Google Cloud CDN": {
        "cats": ["CDN"],
        "headers": {"via": r"google", "server": r"Google Frontend|gws"},
    },
    "KeyCDN": {
        "cats": ["CDN"],
        "headers": {"server": r"keycdn-engine"},
    },
    "BunnyCDN": {
        "cats": ["CDN"],
        "headers": {"server": r"BunnyCDN", "cdn-pullzone": r""},
    },
    "StackPath / Highwinds": {
        "cats": ["CDN"],
        "headers": {"server": r"StackPath|HW", "x-hw": r""},
    },
    "jsDelivr": {
        "cats": ["CDN"],
        "html": [r"cdn\.jsdelivr\.net"],
    },
    "cdnjs (Cloudflare)": {
        "cats": ["CDN"],
        "html": [r"cdnjs\.cloudflare\.com"],
    },
    "unpkg": {
        "cats": ["CDN"],
        "html": [r"unpkg\.com"],
    },
    "Cloudinary": {
        "cats": ["CDN", "Media"],
        "html": [r"res\.cloudinary\.com"],
    },
    "imgix": {
        "cats": ["CDN", "Media"],
        "html": [r"\.imgix\.net"],
    },

    # ---------------- WAF -------------------------------------------------
    "Cloudflare WAF": {
        "cats": ["WAF"],
        "headers": {"cf-ray": r"", "server": r"cloudflare"},
        "html": [r"Attention Required! \| Cloudflare|cf-error-details"],
        "implies": ["Cloudflare"],
    },
    "Akamai Kona": {
        "cats": ["WAF"],
        "headers": {"server": r"AkamaiGHost", "x-akamai-": r""},
        "implies": ["Akamai"],
    },
    "AWS WAF": {
        "cats": ["WAF"],
        "headers": {"x-amzn-requestid": r"", "x-amz-apigw-id": r"",
                    "x-amzn-waf-": r""},
    },
    "Imperva (Incapsula)": {
        "cats": ["WAF"],
        "headers": {"x-iinfo": r"", "x-cdn": r"Incapsula", "set-cookie": r"visid_incap|incap_ses"},
        "cookies": {"visid_incap_": r"", "incap_ses_": r""},
    },
    "Sucuri": {
        "cats": ["WAF"],
        "headers": {"server": r"Sucuri/Cloudproxy", "x-sucuri-id": r"", "x-sucuri-cache": r""},
    },
    "F5 BIG-IP ASM": {
        "cats": ["WAF", "Load balancer"],
        "headers": {"set-cookie": r"BIGipServer|TS[0-9a-f]{8}", "server": r"BIG-?IP|BigIP"},
        "cookies": {"BIGipServer": r""},
    },
    "Citrix NetScaler": {
        "cats": ["WAF", "Load balancer"],
        "headers": {"set-cookie": r"ns_af=|citrix_ns_id|NSC_"},
        "cookies": {"NSC_": r""},
    },
    "ModSecurity": {
        "cats": ["WAF"],
        "headers": {"server": r"mod_security|Mod_Security|NOYB"},
    },
    "Barracuda": {
        "cats": ["WAF"],
        "headers": {"set-cookie": r"barra_counter_session|BNI__BARRACUDA"},
    },
    "Fortinet FortiWeb": {
        "cats": ["WAF"],
        "headers": {"set-cookie": r"FORTIWAFSID", "server": r"FortiWeb"},
    },
    "Wallarm": {
        "cats": ["WAF"],
        "headers": {"server": r"nginx-wallarm|wallarm"},
    },
    "Signal Sciences": {
        "cats": ["WAF"],
        "headers": {"x-sigsci-": r"", "server": r"Signal Sciences"},
    },
    "Wordfence": {
        "cats": ["WAF", "Security"],
        "html": [r"wordfence|wfls-"],
        "implies": ["WordPress"],
    },
    "DDoS-Guard": {
        "cats": ["WAF"],
        "headers": {"server": r"ddos-guard", "set-cookie": r"__ddg"},
    },
    "Reblaze": {
        "cats": ["WAF"],
        "headers": {"set-cookie": r"rbzid", "server": r"Reblaze"},
    },

    # ---------------- Hosting / PaaS -------------------------------------
    "Amazon Web Services": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"server": r"AmazonS3|awselb", "x-amz-": r"",
                    "x-amz-request-id": r""},
    },
    "Amazon S3": {
        "cats": ["Hosting", "CDN"],
        "headers": {"server": r"AmazonS3", "x-amz-bucket-region": r""},
        "implies": ["Amazon Web Services"],
    },
    "Microsoft Azure": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"x-azure-ref": r"", "x-aspnet-version": r"", "server": r"Microsoft-Azure"},
    },
    "Google Cloud": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"server": r"Google Frontend|gws", "x-cloud-trace-context": r"",
                    "x-goog-": r""},
    },
    "Vercel": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"server": r"Vercel", "x-vercel-id": r"", "x-vercel-cache": r""},
    },
    "Netlify": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"server": r"Netlify", "x-nf-request-id": r""},
    },
    "GitHub Pages": {
        "cats": ["Hosting", "Static site generator"],
        "headers": {"server": r"GitHub\.com", "x-github-request-id": r""},
    },
    "Heroku": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"server": r"Cowboy", "via": r"vegur"},
    },
    "Fly.io": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"server": r"Fly/", "fly-request-id": r""},
    },
    "Render": {
        "cats": ["PaaS", "Hosting"],
        "headers": {"x-render-origin-server": r"", "server": r"Render"},
    },
    "Firebase Hosting": {
        "cats": ["Hosting", "PaaS"],
        "headers": {"x-served-by": r"Firebase", "server": r"X-Cache"},
        "html": [r"firebaseapp\.com|firebaseio\.com|firebasejs"],
    },
    "DigitalOcean": {
        "cats": ["Hosting", "PaaS"],
        "headers": {"server": r"DigitalOcean"},
    },
    "Cloudflare Pages": {
        "cats": ["Hosting", "PaaS"],
        "headers": {"server": r"cloudflare", "cf-ray": r""},
        "html": [r"\.pages\.dev"],
    },
    "WP Engine": {
        "cats": ["Hosting"],
        "headers": {"x-powered-by": r"WP Engine", "server": r"WP Engine"},
        "implies": ["WordPress"],
    },

    # ---------------- Databases (inferred) -------------------------------
    "MySQL": {
        "cats": ["Database"],
    },
    "PostgreSQL": {
        "cats": ["Database"],
    },

    # ---------------- DNS / email providers ------------------------------
    "Google Workspace": {
        "cats": ["Email", "SaaS"],
        "dns": {"MX": [r"\bgoogle\.com$|googlemail\.com$|aspmx\.l\.google"],
                "TXT": [r"include:_spf\.google\.com"]},
    },
    "Microsoft 365": {
        "cats": ["Email", "SaaS"],
        "dns": {"MX": [r"\.mail\.protection\.outlook\.com$"],
                "TXT": [r"include:spf\.protection\.outlook\.com|MS=ms\d+"]},
    },
    "Zoho Mail": {
        "cats": ["Email"],
        "dns": {"MX": [r"\.zoho\.(?:com|eu)$"], "TXT": [r"include:zoho"]},
    },
    "SendGrid": {
        "cats": ["Email"],
        "dns": {"TXT": [r"include:sendgrid\.net"]},
    },
    "Mailgun": {
        "cats": ["Email"],
        "dns": {"TXT": [r"include:mailgun\.org"]},
    },
    "Amazon SES": {
        "cats": ["Email"],
        "dns": {"TXT": [r"include:amazonses\.com"]},
    },
})


# ===========================================================================
# 2. DETECTION ENGINE  (compiled-once, confidence-scored, version-aware)
# ===========================================================================

# Per-signal base confidence contribution (0-100, aggregated & capped).
SIGNAL_CONFIDENCE = {
    "headers": 95,
    "cookies": 90,
    "meta": 95,
    "dns": 90,
    "script": 75,
    "url": 65,
    "html": 45,
}
MIN_CONFIDENCE = 45        # minimum aggregate confidence to report a tech
IMPLIED_CONFIDENCE = 55    # confidence assigned to purely-implied techs
_RE_FLAGS = re.IGNORECASE


@dataclass
class Detection:
    name: str
    categories: List[str] = field(default_factory=list)
    version: str = ""
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    implied: bool = False
    cpe: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "categories": self.categories,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence[:8],
            "implied": self.implied,
            "cpe": self.cpe,
        }


@dataclass
class Evidence:
    """Everything the engine matches against for a single target."""
    headers: Dict[str, str] = field(default_factory=dict)   # lower-cased
    cookies: Dict[str, str] = field(default_factory=dict)   # name -> value
    meta: Dict[str, str] = field(default_factory=dict)      # lower-cased name -> content
    html: str = ""
    scripts: str = ""                                       # joined <script src> + inline
    url: str = ""
    dns: Dict[str, List[str]] = field(default_factory=dict)


def _compile_safe(pat: str) -> Optional[Pattern]:
    try:
        return re.compile(pat, _RE_FLAGS)
    except re.error:
        return None


class _CompiledFP:
    __slots__ = ("name", "cats", "implies", "excludes", "cpe",
                 "headers", "cookies", "meta", "html", "script", "url", "dns")

    def __init__(self, name: str, spec: Dict[str, Any]):
        self.name = name
        self.cats: List[str] = spec.get("cats", [])
        self.implies: List[str] = spec.get("implies", [])
        self.excludes: List[str] = spec.get("excludes", [])
        self.cpe: str = spec.get("cpe", "")
        self.headers = [(k.lower(), _compile_safe(v)) for k, v in spec.get("headers", {}).items()]
        self.cookies = [(_compile_safe(k), _compile_safe(v) if v else None)
                        for k, v in spec.get("cookies", {}).items()]
        self.meta = [(k.lower(), _compile_safe(v)) for k, v in spec.get("meta", {}).items()]
        self.html = [_compile_safe(p) for p in spec.get("html", [])]
        self.script = [_compile_safe(p) for p in spec.get("script", [])]
        self.url = [_compile_safe(p) for p in spec.get("url", [])]
        self.dns = [(rt.upper(), _compile_safe(p))
                    for rt, pats in spec.get("dns", {}).items() for p in pats]


def _extract_version(m: "re.Match") -> str:
    try:
        gd = m.groupdict()
        v = gd.get("version")
        return v.strip() if v else ""
    except Exception:
        return ""


class DetectionEngine:
    """Compiles the fingerprint DB once; runs fast scored detection."""

    def __init__(self, fingerprints: Dict[str, Dict[str, Any]] = FINGERPRINTS):
        self._fps: List[_CompiledFP] = [
            _CompiledFP(name, spec) for name, spec in fingerprints.items()
        ]
        self._by_name = {fp.name: fp for fp in self._fps}

    # -- single-signal matching helpers (each returns (matched, version)) --
    @staticmethod
    def _match_value(rx: Optional[Pattern], value: str) -> Tuple[bool, str]:
        if rx is None:
            return False, ""
        m = rx.search(value)
        if m:
            return True, _extract_version(m)
        return False, ""

    def _match_fp(self, fp: "_CompiledFP", ev: Evidence) -> Optional[Detection]:
        conf = 0
        version = ""
        evid: List[str] = []

        def bump(kind: str, label: str, ver: str):
            nonlocal conf, version
            conf += SIGNAL_CONFIDENCE[kind]
            evid.append(f"{kind}:{label}")
            if ver and not version:
                # store the cleanest version we find
                pass

        # headers
        for hdr, rx in fp.headers:
            if hdr in ev.headers:
                ok, ver = self._match_value(rx, ev.headers[hdr])
                if ok:
                    bump("headers", hdr, ver)
                    if ver and not version:
                        version = ver
        # cookies (key regex matches cookie NAME)
        for name_rx, val_rx in fp.cookies:
            if name_rx is None:
                continue
            for cname, cval in ev.cookies.items():
                if name_rx.search(cname):
                    if val_rx is not None and not val_rx.search(cval or ""):
                        continue
                    bump("cookies", cname, "")
                    break
        # meta
        for name, rx in fp.meta:
            if name in ev.meta:
                ok, ver = self._match_value(rx, ev.meta[name])
                if ok:
                    bump("meta", name, ver)
                    if ver and not version:
                        version = ver
        # script srcs / inline
        for rx in fp.script:
            ok, ver = self._match_value(rx, ev.scripts)
            if ok:
                bump("script", "src", ver)
                if ver and not version:
                    version = ver
                break
        # html body
        for rx in fp.html:
            ok, ver = self._match_value(rx, ev.html)
            if ok:
                bump("html", "body", ver)
                if ver and not version:
                    version = ver
                break
        # url
        for rx in fp.url:
            ok, ver = self._match_value(rx, ev.url)
            if ok:
                bump("url", "path", ver)
                break
        # dns
        for rt, rx in fp.dns:
            if rx is None:
                continue
            for rec in ev.dns.get(rt, []):
                if rx.search(rec):
                    bump("dns", rt, "")
                    break

        if conf <= 0:
            return None
        conf = min(conf, 100)
        if conf < MIN_CONFIDENCE:
            return None
        return Detection(
            name=fp.name, categories=list(fp.cats), version=version,
            confidence=conf, evidence=evid, implied=False, cpe=fp.cpe,
        )

    def detect(self, ev: Evidence) -> List[Detection]:
        found: Dict[str, Detection] = {}
        for fp in self._fps:
            det = self._match_fp(fp, ev)
            if det:
                found[fp.name] = det

        # Resolve implied technologies transitively.
        queue = list(found.keys())
        while queue:
            cur = queue.pop()
            fp = self._by_name.get(cur)
            if not fp:
                continue
            for imp in fp.implies:
                if imp in found:
                    continue
                imp_fp = self._by_name.get(imp)
                cats = list(imp_fp.cats) if imp_fp else []
                cpe = imp_fp.cpe if imp_fp else ""
                found[imp] = Detection(
                    name=imp, categories=cats, version="",
                    confidence=IMPLIED_CONFIDENCE,
                    evidence=[f"implied-by:{cur}"], implied=True, cpe=cpe,
                )
                queue.append(imp)

        # Apply excludes.
        for fp in self._fps:
            if fp.name in found and fp.excludes:
                for ex in fp.excludes:
                    found.pop(ex, None)

        # Sort: direct before implied, then by confidence desc, then name.
        return sorted(
            found.values(),
            key=lambda d: (d.implied, -d.confidence, d.name.lower()),
        )


# A single shared engine instance (compiled once for the whole process).
ENGINE = DetectionEngine()


def categories_rollup(dets: List[Detection]) -> Dict[str, List[str]]:
    """Group detected technologies by category for a quick stack overview."""
    out: Dict[str, List[str]] = defaultdict(list)
    for d in dets:
        label = d.name + (f" {d.version}" if d.version else "")
        for c in (d.categories or ["Other"]):
            if label not in out[c]:
                out[c].append(label)
    return dict(sorted(out.items()))


# ===========================================================================
# 3. STATIC CONFIG  (probes, ports, headers)
# ===========================================================================

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36")

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_UA,
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

SECURITY_HEADERS: List[Tuple[str, str]] = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
    ("x-permitted-cross-domain-policies", "X-Permitted-Cross-Domain-Policies"),
    ("x-xss-protection", "X-XSS-Protection (deprecated)"),
]
# Weighted headers used for the A-F security grade.
SECURITY_GRADE_WEIGHTS: Dict[str, int] = {
    "strict-transport-security": 25,
    "content-security-policy": 25,
    "x-frame-options": 15,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10,
    "cross-origin-opener-policy": 5,
}


# ===========================================================================
# 4. DATA MODEL
# ===========================================================================

@dataclass
class TargetResult:
    """Holds every fingerprint we collected for a single target."""
    target: str
    timestamp: str = ""
    final_url: str = ""
    tls: Dict[str, Any] = field(default_factory=dict)
    http_versions: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    status_code: Optional[int] = None
    server: str = ""
    powered_by: str = ""
    aspnet_version: str = ""
    generator: str = ""
    via: str = ""
    x_cache: str = ""
    x_cdn: str = ""
    set_cookie: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    security_headers: Dict[str, bool] = field(default_factory=dict)
    security_grade: str = ""
    security_score: int = 0
    # NEW: rich scored detections + category roll-up.
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    categories: Dict[str, List[str]] = field(default_factory=dict)
    # Back-compat flat lists (derived from `technologies`).
    wafs: List[str] = field(default_factory=list)
    cdns: List[str] = field(default_factory=list)
    frontends: List[str] = field(default_factory=list)
    backends: List[str] = field(default_factory=list)
    cms: List[str] = field(default_factory=list)
    js_libraries: List[str] = field(default_factory=list)
    analytics: List[str] = field(default_factory=list)
    favicon_md5: str = ""
    favicon_mmh3: str = ""
    http3: bool = False
    meta_tags: Dict[str, str] = field(default_factory=dict)
    opengraph: Dict[str, str] = field(default_factory=dict)
    manifest: Dict[str, Any] = field(default_factory=dict)
    source_maps: List[str] = field(default_factory=list)
    title: str = ""
    body_size: int = 0
    body_hashes: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===========================================================================
# 5. UTILITIES
# ===========================================================================

def normalise_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw.rstrip("/") if raw.count("/") == 2 else raw


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def shodan_favicon_mmh3(favicon_bytes: bytes) -> Optional[str]:
    """Shodan-compatible favicon hash: mmh3 over base64 (with newlines)."""
    if mmh3 is None:
        return None
    try:
        b64 = base64.encodebytes(favicon_bytes)
        return str(mmh3.hash(b64))
    except Exception:
        return None


def extract_html_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return clean(re.sub(r"\s+", " ", m.group(1))) if m else ""


def extract_meta_tags(html: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not html:
        return out
    if _HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("meta"):
                key = tag.get("name") or tag.get("property") or tag.get("http-equiv")
                content = tag.get("content")
                if key and content is not None:
                    out[key.lower()] = content
            return out
        except Exception:
            pass
    for m in re.finditer(
        r"<meta\s+[^>]*?(?:name|property)\s*=\s*[\"']([^\"']+)[\"']"
        r"[^>]*?content\s*=\s*[\"']([^\"']*)[\"']", html, re.IGNORECASE):
        out[m.group(1).lower()] = m.group(2)
    for m in re.finditer(
        r"<meta\s+[^>]*?content\s*=\s*[\"']([^\"']*)[\"']"
        r"[^>]*?(?:name|property)\s*=\s*[\"']([^\"']+)[\"']", html, re.IGNORECASE):
        out[m.group(2).lower()] = m.group(1)
    return out


def extract_opengraph(meta: Dict[str, str]) -> Dict[str, str]:
    return {k: v for k, v in meta.items() if k.startswith("og:")}


def extract_script_srcs(html: str) -> List[str]:
    return [s for s in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',
                                  html, re.IGNORECASE) if s]


def extract_inline_scripts(html: str) -> str:
    """Concatenate a bounded amount of inline <script> content for matching."""
    chunks = re.findall(r"<script[^>]*>(.*?)</script>", html,
                        re.IGNORECASE | re.DOTALL)
    blob = "\n".join(chunks)
    return blob[:200_000]


def extract_link_hrefs(html: str) -> List[str]:
    return re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)


def parse_cookies_from_headers(set_cookie_values: List[str]) -> Dict[str, str]:
    """Parse cookie name=value pairs from raw Set-Cookie header lines."""
    out: Dict[str, str] = {}
    for raw in set_cookie_values:
        first = raw.split(";", 1)[0].strip()
        if "=" in first:
            k, v = first.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def compute_security_grade(headers: Dict[str, str]) -> Tuple[str, int]:
    score = sum(w for h, w in SECURITY_GRADE_WEIGHTS.items() if h in headers)
    score = min(score, 100)
    if score >= 90:
        g = "A+"
    elif score >= 75:
        g = "A"
    elif score >= 60:
        g = "B"
    elif score >= 40:
        g = "C"
    elif score >= 20:
        g = "D"
    else:
        g = "F"
    return g, score


# ===========================================================================
# 6. ASYNC SCANNER  (shared session, concurrent targets, single-fetch reuse)
# ===========================================================================

@dataclass
class _RespSnapshot:
    status: int
    url: str
    headers: Dict[str, str]
    raw_headers: Any
    history: List[str]
    version: Any
    peercert: Optional[bytes] = None
    tls_proto: str = ""
    tls_cipher: str = ""


class TechFingerprint:
    """Main scanner. ONE aiohttp session is shared across every target/probe."""

    def __init__(
        self,
        concurrency: int = 40,
        target_concurrency: int = 10,
        timeout: Optional[float] = None,
        retries: int = 1,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        verify_tls: bool = False,
        follow_redirects: bool = True,
        rate_limit_per_sec: Optional[float] = None,
        verbose: bool = False,
        user_agent: str = DEFAULT_UA,
        deep: bool = True,
    ):
        self.concurrency = max(1, concurrency)
        self.target_concurrency = max(1, target_concurrency)
        self.timeout = ClientTimeout(total=timeout) if timeout is not None else None
        self.timeout_total = timeout
        self.retries = max(0, retries)
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.headers = dict(DEFAULT_HEADERS)
        self.headers["User-Agent"] = user_agent
        if extra_headers:
            self.headers.update(extra_headers)
        if not _HAS_BROTLI and "br" in self.headers.get("Accept-Encoding", ""):
            # brotli package isn't importable in this environment -> aiohttp
            # cannot decode a br-encoded response and would raise
            # ClientPayloadError. Don't advertise support we can't honor.
            self.headers["Accept-Encoding"] = ", ".join(
                enc.strip() for enc in self.headers["Accept-Encoding"].split(",")
                if enc.strip().lower() != "br"
            )
        self.cookies = cookies or {}
        self.rate_limit = rate_limit_per_sec
        self.deep = deep
        self.engine = ENGINE

        self._sem: Optional[asyncio.Semaphore] = None
        self._target_sem: Optional[asyncio.Semaphore] = None
        self._rate_lock = asyncio.Lock()
        self._last_request_at = 0.0
        self._session: Optional[ClientSession] = None
        self._ssl_ctx = self._make_ssl_context()

    def _make_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ----------------- session lifecycle ---------------------------------
    async def _ensure_session(self) -> ClientSession:
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=self.concurrency,
                limit_per_host=min(self.concurrency, 12),
                ssl=self._ssl_ctx,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
                force_close=False,
            )
            self._session = ClientSession(
                timeout=self.timeout,
                connector=connector,
                cookies=self.cookies,
                trust_env=True,
                cookie_jar=aiohttp.CookieJar(unsafe=True),
                auto_decompress=True,
                max_line_size=65536,
                max_field_size=65536,
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "TechFingerprint":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    # ----------------- public API ----------------------------------------
    async def scan(self, target: str) -> TargetResult:
        target = normalise_target(target)
        result = TargetResult(target=target, timestamp=now_iso())
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.concurrency)
        await self._ensure_session()
        try:
            await self._gather_all(target, result)
        except Exception as exc:  # pragma: no cover
            result.errors.append(f"FATAL: {type(exc).__name__}: {exc}")
        self._finalise(result)
        return result

    async def scan_many(self, targets: List[str]) -> List[TargetResult]:
        self._sem = asyncio.Semaphore(self.concurrency)
        self._target_sem = asyncio.Semaphore(self.target_concurrency)
        await self._ensure_session()

        async def _one(t: str) -> TargetResult:
            async with self._target_sem:  # type: ignore
                return await self.scan(t)

        try:
            return await asyncio.gather(*[_one(t) for t in targets])
        finally:
            await self.close()

    # ----------------- HTTP helper ---------------------------------------
    async def _request(self, method: str, url: str, *, allow_redirects: bool,
                       read: bool = True) -> Optional[Tuple[Any, bytes]]:
        """One throttled, semaphore-guarded request with retries.
        Returns (response, body_bytes) — response is detached (already read)."""
        session = await self._ensure_session()
        attempt = 0
        while True:
            try:
                await self._throttle()
                async with self._sem:  # type: ignore
                    async with session.request(
                        method, url, headers=self.headers,
                        allow_redirects=allow_redirects, proxy=self.proxy,
                    ) as resp:
                        try:
                            body = await resp.read() if read else b""
                        except aiohttp.ClientPayloadError:
                            # Server sent a Content-Encoding aiohttp/brotli
                            # couldn't decode (e.g. br without the brotli
                            # package, or a malformed/truncated stream).
                            # Fall back to the raw, undecoded bytes so the
                            # scan still gets headers/TLS/status instead of
                            # failing the target outright. Body-text-based
                            # fingerprints may be skipped for this target.
                            try:
                                raw = resp.content._buffer if hasattr(
                                    resp.content, "_buffer") else b""
                                body = bytes(raw) if raw else b""
                            except Exception:
                                body = b""
                        # Capture the peer cert + TLS params from the LIVE
                        # connection before the context manager closes it.
                        peercert = None
                        tls_proto = tls_cipher = ""
                        try:
                            conn = resp.connection
                            tr = conn.transport if conn else None
                            ssl_obj = tr.get_extra_info("ssl_object") if tr else None
                            if ssl_obj is not None:
                                peercert = ssl_obj.getpeercert(binary_form=True)
                                tls_proto = ssl_obj.version() or ""
                                cph = ssl_obj.cipher()
                                tls_cipher = cph[0] if cph else ""
                        except Exception:
                            pass
                        snap = _RespSnapshot(
                            status=resp.status,
                            url=str(resp.url),
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            raw_headers=resp.headers,
                            history=[str(h.url) for h in resp.history],
                            version=resp.version,
                            peercert=peercert,
                            tls_proto=tls_proto,
                            tls_cipher=tls_cipher,
                        )
                        return snap, body
            except (asyncio.TimeoutError, aiohttp.ClientError) as exc:
                attempt += 1
                if attempt > self.retries:
                    raise
                await asyncio.sleep(0.3 * attempt)

    # ----------------- orchestration -------------------------------------
    async def _gather_all(self, target: str, r: TargetResult) -> None:
        st: Dict[str, Any] = {"text": "", "scripts": "", "script_srcs": []}
        # Base request first (everything else depends on headers/body).
        await self._do_base_request(target, r, st)
        # Then lighter probes in parallel, reusing the shared session.
        coros = [
            self._probe_http2_http3(target, r),
            self._probe_assets(target, r, st),
            self._probe_favicon(target, r),
        ]
        # TLS only via dedicated probe if base request didn't capture it.
        if target.startswith("https://") and not r.tls:
            coros.append(self._probe_tls(target, r))
        await asyncio.gather(*coros, return_exceptions=True)

    # ----------------- rate limiting -------------------------------------
    async def _throttle(self) -> None:
        if not self.rate_limit:
            return
        async with self._rate_lock:
            now = time.monotonic()
            wait = (1.0 / self.rate_limit) - (now - self._last_request_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()


    # ----------------- base request --------------------------------------
    async def _do_base_request(self, target: str, r: TargetResult,
                               st: Dict[str, Any]) -> None:
        try:
            t0 = time.monotonic()
            res = await self._request("GET", target,
                                      allow_redirects=self.follow_redirects)
            if res is None:
                r.errors.append("HTTP base request returned no response")
                return
            snap, body = res
            r.response_time_ms = round((time.monotonic() - t0) * 1000.0, 2)
            r.status_code = snap.status
            r.final_url = snap.url
            r.redirect_chain = snap.history
            ver = snap.version
            if hasattr(ver, "major") and hasattr(ver, "minor"):
                r.http_versions = [f"HTTP/{ver.major}.{ver.minor}"]
            else:
                r.http_versions = [f"HTTP/{ver}"]

            hdrs = snap.headers
            r.headers = hdrs
            r.server = clean(hdrs.get("server", ""))
            r.powered_by = clean(hdrs.get("x-powered-by", ""))
            r.aspnet_version = clean(hdrs.get("x-aspnet-version", ""))
            r.generator = clean(hdrs.get("x-generator", ""))
            r.via = clean(hdrs.get("via", ""))
            r.x_cache = clean(hdrs.get("x-cache", ""))
            r.x_cdn = clean(hdrs.get("x-cdn", ""))
            # Collect ALL Set-Cookie lines (aiohttp merges, so use raw headers).
            set_cookies: List[str] = []
            try:
                set_cookies = [v for (k, v) in snap.raw_headers.items()
                               if k.lower() == "set-cookie"]
            except Exception:
                if "set-cookie" in hdrs:
                    set_cookies = [hdrs["set-cookie"]]
            r.set_cookie = [c for c in set_cookies if "=" in c][:25]

            r.security_headers = {label: (hdr in hdrs) for hdr, label in SECURITY_HEADERS}

            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = body.decode("latin-1", errors="replace")
            r.body_size = len(body)
            r.body_hashes = {
                "md5": md5_hex(body),
                "sha1": hashlib.sha1(body).hexdigest(),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
            r.title = extract_html_title(text)
            r.meta_tags = extract_meta_tags(text)
            r.opengraph = extract_opengraph(r.meta_tags)

            # Cache body bits for reuse by later probes (no re-fetch!).
            srcs = extract_script_srcs(text)
            st["text"] = text
            st["script_srcs"] = srcs
            st["scripts"] = "\n".join(srcs + [extract_inline_scripts(text)])

            # TLS captured from the same connection (no second handshake).
            if snap.peercert:
                r.tls = self._parse_der_cert(snap.peercert)
                if snap.tls_proto:
                    r.tls["protocol"] = snap.tls_proto
                if snap.tls_cipher:
                    r.tls["cipher"] = snap.tls_cipher

            # ---- Run the detection engine -------------------------------
            self._detect(r, st, set_cookies)

        except asyncio.TimeoutError:
            r.errors.append("HTTP timeout on base request")
        except aiohttp.ClientError as exc:
            r.errors.append(f"HTTP client error: {type(exc).__name__}: {exc}")
        except Exception as exc:
            r.errors.append(f"HTTP error: {type(exc).__name__}: {exc}")

    # ----------------- detection wiring ----------------------------------
    def _detect(self, r: TargetResult, st: Dict[str, Any],
                set_cookies: List[str]) -> None:
        # Header blob keyed for engine: include a joined set-cookie value so
        # cookie-in-header regexes still match, plus a generic 'link' header.
        headers = dict(r.headers)
        if set_cookies:
            headers["set-cookie"] = " ; ".join(set_cookies)
        ev = Evidence(
            headers=headers,
            cookies=parse_cookies_from_headers(set_cookies),
            meta=r.meta_tags,
            html=st.get("text", ""),
            scripts=st.get("scripts", ""),
            url=f"{r.final_url}\n{host_of(r.final_url or r.target)}",
            dns={},
        )
        dets = self.engine.detect(ev)
        r.technologies = [d.to_dict() for d in dets]
        r.categories = categories_rollup(dets)

    def _finalise(self, r: TargetResult) -> None:
        """Derive back-compat flat lists + security grade from detections."""
        cat_map = {
            "wafs": {"WAF"},
            "cdns": {"CDN"},
            "frontends": {"JavaScript framework", "UI framework"},
            "backends": {"Web framework", "Programming language",
                         "Application server", "Web server", "Runtime"},
            "cms": {"CMS", "Headless CMS", "Website builder", "Blog"},
            "js_libraries": {"JavaScript library"},
            "analytics": {"Analytics", "Tag manager", "RUM", "A/B testing"},
        }
        for attr, cats in cat_map.items():
            vals: List[str] = []
            for d in r.technologies:
                if set(d.get("categories", [])) & cats:
                    label = d["name"] + (f" {d['version']}" if d.get("version") else "")
                    if label not in vals:
                        vals.append(label)
            setattr(r, attr, sorted(vals))
        r.security_grade, r.security_score = compute_security_grade(r.headers)

    @staticmethod
    def _parse_der_cert(der_bytes: bytes) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtensionOID
            cert = x509.load_der_x509_certificate(der_bytes)
            subj, iss = cert.subject, cert.issuer

            def _get(name, oid):
                try:
                    attrs = name.get_attributes_for_oid(oid)
                    return attrs[0].value if attrs else ""
                except Exception:
                    return ""

            out["subject_cn"] = _get(subj, NameOID.COMMON_NAME)
            out["subject_org"] = _get(subj, NameOID.ORGANIZATION_NAME)
            out["issuer_cn"] = _get(iss, NameOID.COMMON_NAME)
            out["issuer_org"] = _get(iss, NameOID.ORGANIZATION_NAME)
            out["not_before"] = (cert.not_valid_before_utc.isoformat()
                                 if hasattr(cert, "not_valid_before_utc")
                                 else str(cert.not_valid_before))
            out["not_after"] = (cert.not_valid_after_utc.isoformat()
                                if hasattr(cert, "not_valid_after_utc")
                                else str(cert.not_valid_after))
            out["serial"] = format(cert.serial_number, "x")
            out["version"] = cert.version.name
            try:
                ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                out["san"] = [str(n.value) for n in ext.value]
            except Exception:
                out["san"] = []
            # Days until expiry (handy operational signal).
            try:
                exp = (cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc")
                       else cert.not_valid_after.replace(tzinfo=timezone.utc))
                out["days_to_expiry"] = (exp - datetime.now(timezone.utc)).days
            except Exception:
                pass
        except ImportError:
            out["error"] = "cryptography not installed"
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    # ----------------- TLS fallback probe --------------------------------
    async def _probe_tls(self, target: str, r: TargetResult) -> None:
        host = host_of(target)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host),
                timeout=self.timeout_total)
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
                if der:
                    r.tls = self._parse_der_cert(der)
                    try:
                        r.tls["protocol"] = ssl_obj.version() or ""
                        c = ssl_obj.cipher()
                        r.tls["cipher"] = c[0] if c else ""
                    except Exception:
                        pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except asyncio.TimeoutError:
            r.errors.append("TLS probe timeout")
        except Exception as exc:
            r.errors.append(f"TLS probe error: {type(exc).__name__}: {exc}")

    # ----------------- HTTP/2 + HTTP/3 -----------------------------------
    async def _probe_http2_http3(self, target: str, r: TargetResult) -> None:
        alt_svc = r.headers.get("alt-svc", "")
        if "h3" in alt_svc or "quic" in alt_svc:
            r.http3 = True
            r.http_versions = sorted(set(r.http_versions + ["HTTP/3 (advertised)"]))
        if "h2" in alt_svc:
            r.http_versions = sorted(set(r.http_versions + ["HTTP/2 (advertised)"]))


    # ----------------- specific endpoint probes --------------------------
    # ----------------- favicon hash --------------------------------------
    async def _probe_favicon(self, target: str, r: TargetResult) -> None:
        candidates = [urljoin(target + "/", "favicon.ico"),
                      urljoin(target + "/", "favicon.png")]
        for url in candidates:
            try:
                res = await self._request("GET", url, allow_redirects=True)
                if res is None:
                    continue
                snap, body = res
                if snap.status != 200 or not body or len(body) < 20:
                    continue
                r.favicon_md5 = md5_hex(body)
                mh = shodan_favicon_mmh3(body)
                if mh:
                    r.favicon_mmh3 = mh
                break
            except Exception:
                continue

    # ----------------- asset probes (manifest + source maps, reuses body) -
    async def _probe_assets(self, target: str, r: TargetResult,
                            st: Dict[str, Any]) -> None:
        # 1. manifest.json content
        try:
            res = await self._request("GET", urljoin(target + "/", "manifest.json"),
                                      allow_redirects=True)
            if res is not None:
                snap, body = res
                if snap.status == 200 and body:
                    try:
                        r.manifest = json.loads(body.decode("utf-8", errors="replace"))
                    except Exception:
                        r.manifest = {"raw": body[:500].decode("utf-8", errors="replace")}
        except Exception:
            pass

        if not self.deep:
            return

        # 2. Source maps — reuse the script srcs already extracted (NO re-fetch).
        js_srcs = [s for s in st.get("script_srcs", []) if s.endswith(".js")][:30]
        if not js_srcs:
            return

        async def _check_map(src: str) -> Optional[str]:
            map_url = urljoin(target + "/", src) + ".map"
            try:
                res = await self._request("HEAD", map_url, allow_redirects=False,
                                          read=False)
                if res is not None and res[0].status == 200:
                    return map_url
            except Exception:
                return None
            return None

        maps = await asyncio.gather(*[_check_map(s) for s in js_srcs])
        r.source_maps = [m for m in maps if m]


# ===========================================================================
# 7. OUTPUT
# ===========================================================================

def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{Style.RESET_ALL}"


def _conf_colour(conf: int) -> str:
    if conf >= 90:
        return Fore.GREEN
    if conf >= 60:
        return Fore.CYAN
    return Fore.YELLOW


def print_result_console(r: TargetResult) -> None:
    line = "=" * 70
    print(_c(line, Fore.BLUE))
    print(_c(f" TARGET: {r.target}", Fore.WHITE + Style.BRIGHT))
    print(_c(line, Fore.BLUE))
    if r.final_url and r.final_url != r.target:
        print(f"  Final URL    : {r.final_url}")
    print(f"  Status       : {r.status_code}   ({r.response_time_ms} ms)")
    if r.http_versions:
        print(f"  HTTP         : {', '.join(r.http_versions)}")
    if r.title:
        print(f"  Title        : {r.title[:80]}")
    if r.server:
        print(f"  Server       : {r.server}")

    # --- Technologies grouped by category ---
    if r.categories:
        print(_c("\n  ── Detected technologies ───────────────────────────", Fore.MAGENTA))
        for cat, items in r.categories.items():
            print(f"  {_c(cat + ':', Fore.WHITE + Style.BRIGHT)} {', '.join(items)}")
    # --- Confidence table ---
    if r.technologies:
        print(_c("\n  ── Confidence ──────────────────────────────────────", Fore.MAGENTA))
        for d in r.technologies:
            tag = "≈" if d.get("implied") else "•"
            name = d["name"] + (f" {d['version']}" if d.get("version") else "")
            conf = d.get("confidence", 0)
            print("   " + _c(f"{tag} {name:<34}", _conf_colour(conf))
                  + _c(f"{conf:>3}%", _conf_colour(conf))
                  + f"  [{', '.join(d.get('categories', [])[:2])}]")

    # --- TLS ---
    if r.tls and not r.tls.get("error"):
        print(_c("\n  ── TLS ─────────────────────────────────────────────", Fore.MAGENTA))
        print(f"   Issuer  : {r.tls.get('issuer_org') or r.tls.get('issuer_cn','')}")
        print(f"   Subject : {r.tls.get('subject_cn','')}")
        print(f"   Proto   : {r.tls.get('protocol','')}  {r.tls.get('cipher','')}")
        if "days_to_expiry" in r.tls:
            print(f"   Expires : in {r.tls['days_to_expiry']} days")

    # --- Security headers + grade ---
    present = [lbl for lbl, ok in r.security_headers.items() if ok]
    grade_colour = (Fore.GREEN if r.security_grade in ("A+", "A")
                    else Fore.YELLOW if r.security_grade in ("B", "C")
                    else Fore.RED)
    print(_c("\n  ── Security ────────────────────────────────────────", Fore.MAGENTA))
    print("   Grade   : " + _c(f"{r.security_grade} ({r.security_score}/100)", grade_colour))
    print(f"   Headers : {', '.join(present) if present else 'none'}")

    if r.favicon_mmh3 or r.favicon_md5:
        print(_c("\n  ── Favicon ─────────────────────────────────────────", Fore.MAGENTA))
        print(f"   mmh3 (Shodan http.favicon.hash): {r.favicon_mmh3}")
        print(f"   md5 : {r.favicon_md5}")

    if r.source_maps:
        print(_c(f"\n  Source maps exposed: {len(r.source_maps)}", Fore.YELLOW))
    if r.errors:
        print(_c("\n  Errors: " + "; ".join(r.errors[:5]), Fore.YELLOW))
    print()


def _json_dump(obj: Any) -> bytes:
    if _HAS_ORJSON:
        return orjson.dumps(obj, option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS)
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False).encode("utf-8")


def write_json(results: List[TargetResult], path: str) -> None:
    payload = {"tool": __prog__, "version": __version__,
               "generated": now_iso(),
               "results": [r.to_dict() for r in results]}
    with open(path, "wb") as f:
        f.write(_json_dump(payload))


def write_csv(results: List[TargetResult], path: str) -> None:
    cols = ["target", "final_url", "status_code", "response_time_ms",
            "server", "security_grade", "technologies", "categories"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in results:
            techs = "; ".join(
                d["name"] + (f" {d['version']}" if d.get("version") else "")
                + f" ({d.get('confidence',0)}%)"
                for d in r.technologies if not d.get("implied"))
            cats = " | ".join(f"{c}: {', '.join(v)}" for c, v in r.categories.items())
            w.writerow([
                r.target, r.final_url, r.status_code, r.response_time_ms,
                r.server, f"{r.security_grade} ({r.security_score})",
                techs, cats,
            ])


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TechFingerprint Report</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--bd:#30363d;--fg:#e6edf3;--mut:#8b949e;
        --acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);
       font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}}
  header{{padding:24px 32px;border-bottom:1px solid var(--bd);}}
  h1{{margin:0;font-size:20px}} .sub{{color:var(--mut);font-size:13px}}
  .wrap{{padding:24px 32px;max-width:1100px;margin:0 auto}}
  .card{{background:var(--card);border:1px solid var(--bd);border-radius:10px;
        padding:20px;margin-bottom:22px}}
  .row{{display:flex;flex-wrap:wrap;gap:8px 18px;color:var(--mut);font-size:13px}}
  .row b{{color:var(--fg)}}
  h2{{font-size:15px;margin:18px 0 8px;color:var(--acc)}}
  .chips{{display:flex;flex-wrap:wrap;gap:6px}}
  .chip{{background:#21262d;border:1px solid var(--bd);border-radius:20px;
        padding:3px 11px;font-size:12px}}
  .cat{{margin:6px 0}} .cat .lbl{{display:inline-block;min-width:160px;color:var(--mut)}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid var(--bd)}}
  th{{color:var(--mut);font-weight:600}}
  .bar{{height:7px;border-radius:4px;background:#21262d;overflow:hidden;width:90px;display:inline-block;vertical-align:middle}}
  .bar>i{{display:block;height:100%}}
  .imp{{color:var(--mut)}} .grade{{font-weight:700;font-size:16px}}
  .leak{{color:var(--bad);font-weight:600}}
  code{{background:#21262d;padding:1px 5px;border-radius:4px}}
</style></head><body>
<header><h1>🔬 TechFingerprint Report</h1>
<div class="sub">{generated} · v{version} · {count} target(s)</div></header>
<div class="wrap">{body}</div></body></html>"""


def _bar(conf: int) -> str:
    col = "var(--ok)" if conf >= 90 else "var(--acc)" if conf >= 60 else "var(--warn)"
    return (f'<span class="bar"><i style="width:{conf}%;background:{col}"></i></span>'
            f' {conf}%')


def render_target_html(r: TargetResult) -> str:
    e = html_lib.escape
    parts = [f'<div class="card"><h1 style="font-size:17px;margin:0 0 10px">{e(r.target)}</h1>']
    parts.append('<div class="row">'
                 f'<span>Status <b>{r.status_code}</b></span>'
                 f'<span>Time <b>{r.response_time_ms} ms</b></span>'
                 f'<span>Server <b>{e(r.server or "—")}</b></span>'
                 f'<span>HTTP <b>{e(", ".join(r.http_versions) or "—")}</b></span>'
                 f'<span>Security <b class="grade">{r.security_grade}</b> ({r.security_score}/100)</span>'
                 '</div>')
    if r.final_url and r.final_url != r.target:
        parts.append(f'<div class="row"><span>Final URL <b>{e(r.final_url)}</b></span></div>')

    if r.categories:
        parts.append("<h2>Stack by category</h2>")
        for cat, items in r.categories.items():
            chips = "".join(f'<span class="chip">{e(i)}</span>' for i in items)
            parts.append(f'<div class="cat"><span class="lbl">{e(cat)}</span> '
                         f'<span class="chips" style="display:inline-flex">{chips}</span></div>')

    if r.technologies:
        parts.append("<h2>Detections &amp; confidence</h2><table>"
                     "<tr><th>Technology</th><th>Version</th><th>Confidence</th>"
                     "<th>Categories</th><th>Evidence</th></tr>")
        for d in r.technologies:
            cls = ' class="imp"' if d.get("implied") else ""
            name = e(d["name"]) + (" ≈" if d.get("implied") else "")
            parts.append(
                f"<tr{cls}><td>{name}</td><td>{e(d.get('version',''))}</td>"
                f"<td>{_bar(d.get('confidence',0))}</td>"
                f"<td>{e(', '.join(d.get('categories', [])))}</td>"
                f"<td><code>{e(', '.join(d.get('evidence', [])[:3]))}</code></td></tr>")
        parts.append("</table>")

    if r.tls and not r.tls.get("error"):
        parts.append("<h2>TLS</h2><div class='row'>"
                     f"<span>Issuer <b>{e(r.tls.get('issuer_org') or r.tls.get('issuer_cn',''))}</b></span>"
                     f"<span>Proto <b>{e(r.tls.get('protocol',''))}</b></span>"
                     f"<span>Cipher <b>{e(r.tls.get('cipher',''))}</b></span>"
                     + (f"<span>Expires in <b>{r.tls.get('days_to_expiry')}</b> days</span>"
                        if 'days_to_expiry' in r.tls else "") + "</div>")

    if r.favicon_mmh3:
        parts.append(f"<h2>Favicon</h2><div class='row'><span>Shodan hash "
                     f"<code>http.favicon.hash:{e(r.favicon_mmh3)}</code></span></div>")
    if r.errors:
        parts.append("<h2>Errors</h2><div class='row'>"
                     + " ".join(f"<span>{e(x)}</span>" for x in r.errors[:5]) + "</div>")
    parts.append("</div>")
    return "".join(parts)


def write_html(results: List[TargetResult], path: str) -> None:
    body = "".join(render_target_html(r) for r in results)
    html = _HTML_TEMPLATE.format(generated=now_iso(), version=__version__,
                                 count=len(results), body=body)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def write_txt(results: List[TargetResult], path: str) -> None:
    lines: List[str] = []
    for r in results:
        lines.append("=" * 70)
        lines.append(f"TARGET: {r.target}")
        lines.append("=" * 70)
        lines.append(f"Status: {r.status_code}  ({r.response_time_ms} ms)  "
                     f"Server: {r.server}")
        lines.append(f"Security grade: {r.security_grade} ({r.security_score}/100)")
        if r.categories:
            lines.append("\n-- Technologies by category --")
            for cat, items in r.categories.items():
                lines.append(f"  {cat}: {', '.join(items)}")
        if r.technologies:
            lines.append("\n-- Confidence --")
            for d in r.technologies:
                tag = "~" if d.get("implied") else "*"
                name = d["name"] + (f" {d['version']}" if d.get("version") else "")
                lines.append(f"  {tag} {name} ({d.get('confidence',0)}%)")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ===========================================================================
# 8. CLI
# ===========================================================================

def parse_targets(arg: str) -> List[str]:
    if arg == "-":
        return [l.strip() for l in sys.stdin if l.strip()]
    if arg.startswith("@"):
        path = arg[1:]
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}", file=sys.stderr)
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return [t.strip() for t in arg.split(",") if t.strip()]


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=__prog__,
        description=("TechFingerprint v2 - advanced pure-Python technology "
                     "fingerprinting (Wappalyzer-style, confidence-scored, "
                     "concurrent). No external CLI tools."),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-t", "--target",
                   help="Target(s): single URL, comma-separated, '-' for stdin, '@file.txt'.")
    p.add_argument("-l", "--list", dest="target_list",
                   help="File with targets (one per line, '#' comments).")
    p.add_argument("-c", "--concurrency", type=int, default=40,
                   help="Max concurrent requests across all targets (default 40).")
    p.add_argument("--target-concurrency", type=int, default=10,
                   help="Max targets scanned in parallel (default 10).")
    p.add_argument("--timeout", type=float, default=None,
                   help="Per-request timeout seconds (default: no timeout).")
    p.add_argument("--retries", type=int, default=1, help="Retries (default 1).")
    p.add_argument("--proxy", default=None, help="Proxy URL (http/https/socks5).")
    p.add_argument("--rate", type=float, default=None, help="Max requests/sec.")
    p.add_argument("-A", "--user-agent", default=DEFAULT_UA, help="Custom User-Agent.")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Extra header 'X: y' (repeatable).")
    p.add_argument("--cookie", action="append", default=[],
                   help="Cookie 'k=v' (repeatable).")
    p.add_argument("--verify-tls", action="store_true", help="Verify TLS certs.")
    p.add_argument("--no-redirect", action="store_true", help="Do NOT follow redirects.")
    p.add_argument("--fast", action="store_true",
                   help="Fast mode: skip favicon + source-map asset checks.")
    p.add_argument("-q", "--quiet", action="store_true", help="No console output.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")

    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output-dir", default="techfingerprint_reports",
                     help="Directory for output files.")
    out.add_argument("--json", action="store_true", help="Write JSON report.")
    out.add_argument("--html", action="store_true", help="Write HTML report.")
    out.add_argument("--csv", action="store_true", help="Write CSV report.")
    out.add_argument("--txt", action="store_true", help="Write TXT report.")
    out.add_argument("--all-formats", action="store_true", help="Write all formats.")
    return p


def parse_header_list(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in items:
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_cookie_list(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in items:
        if "=" in c:
            k, v = c.split("=", 1)
            out[k.strip()] = v.strip()
    return out


async def async_main(opts: argparse.Namespace) -> int:
    # Collect targets from -t and/or -l
    targets = []
    if opts.target:
        targets.extend(parse_targets(opts.target))
    if opts.target_list:
        if not os.path.isfile(opts.target_list):
            print(f"[!] Target list file not found: {opts.target_list}", file=sys.stderr)
            return 2
        with open(opts.target_list) as f:
            targets.extend(
                l.strip() for l in f
                if l.strip() and not l.strip().startswith("#")
            )
    if not targets:
        print("[!] No targets specified. Use -t or -l.", file=sys.stderr)
        return 2

    fast = opts.fast
    if not opts.quiet:
        print(_c(f"[*] TechFingerprint v{__version__} - {len(targets)} target(s), "
                 f"req-concurrency={opts.concurrency}, "
                 f"target-concurrency={opts.target_concurrency}, "
                 f"timeout={opts.timeout}s"
                 + ("  [FAST MODE]" if fast else ""), Fore.CYAN))
        print(_c(f"[*] Signature DB: {len(FINGERPRINTS)} technologies loaded", Fore.CYAN))

    scanner = TechFingerprint(
        concurrency=opts.concurrency,
        target_concurrency=opts.target_concurrency,
        timeout=opts.timeout,
        retries=opts.retries,
        proxy=opts.proxy,
        extra_headers=parse_header_list(opts.header),
        cookies=parse_cookie_list(opts.cookie),
        verify_tls=opts.verify_tls,
        follow_redirects=not opts.no_redirect,
        rate_limit_per_sec=opts.rate,
        verbose=opts.verbose,
        user_agent=opts.user_agent,
        deep=not fast,
    )

    t0 = time.monotonic()
    results = await scanner.scan_many(targets)
    elapsed = time.monotonic() - t0

    if not opts.quiet:
        for r in results:
            print_result_console(r)
        print(_c(f"[*] Scanned {len(results)} target(s) in {elapsed:.2f}s "
                 f"({elapsed / max(1, len(results)):.2f}s/target)", Fore.CYAN))

    if opts.all_formats:
        opts.json = opts.html = opts.csv = opts.txt = True
    if not any([opts.json, opts.html, opts.csv, opts.txt]):
        opts.json = True

    out_dir = opts.output_dir
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    writers = [("json", write_json), ("html", write_html),
               ("csv", write_csv), ("txt", write_txt)]
    for ext, fn in writers:
        if getattr(opts, ext):
            path = os.path.join(out_dir, f"techfingerprint_{stamp}.{ext}")
            fn(results, path)
            if not opts.quiet:
                print(_c(f"[+] Wrote {path}", Fore.GREEN))
    return 0


def main() -> int:
    opts = build_argparser().parse_args()
    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    try:
        return asyncio.run(async_main(opts))
    except KeyboardInterrupt:
        print(_c("\n[!] Interrupted.", Fore.YELLOW), file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
