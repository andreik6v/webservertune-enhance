#!/usr/bin/env python3
"""
Tests for woo_bot_protection (overrides/woo-bot.conf + nginxtune integration):

- Included only on WordPress vhosts where WooCommerce is detected under WWW_DIR
  (every component walked with O_NOFOLLOW, regular marker files, bounded child
  scan), skipped for plain WP, static sites, default.conf, symlinked docroots/
  ancestors/subdirs/markers, missing docroots, and woo_bot_allow_domains.
- Cleanly removed when disabled or during cleanup(), idempotent on repeat runs,
  cleans legacy paths, and undone cleanly if nginx -t fails.
- overrides/woo-bot.conf parses cleanly with nginxconf, initialises every
  variable before reading it, blocks crawlers and non-browser HTTPS traps, and
  keeps real shoppers (including direct email/ad links, plain-HTTP redirects,
  CUBOT/in-app browsers, and 3+ value layered-navigation filters) unaffected.
- Optional real-nginx integration test runs automatically when `nginx` is in PATH.

    python3 -m unittest discover -s tests -v
"""

import http.client
import importlib.machinery
import importlib.util
import logging
import os
import pwd
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load(name):
    loader = importlib.machinery.SourceFileLoader(name, str(REPO / "modules" / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


ngx = load("nginxtune")
nc  = load("nginxconf")
LOG = logging.getLogger("test-woo-bot")
LOG.addHandler(logging.NullHandler())


def _eval_woo_bot_conf(conf_text, *, scheme="https", host="shop.example.com",
                       args="", ua="", referer="", sec_fetch_site=""):
    """
    Faithful step-by-step evaluator for the server-level set/if/return
    directives in overrides/woo-bot.conf so unit tests execute the real config
    file rather than duplicated regexes.
    """
    env = {
        "scheme": scheme,
        "host": host,
        "args": args,
        "http_user_agent": ua,
        "http_referer": referer,
        "http_sec_fetch_site": sec_fetch_site,
    }
    var_re = re.compile(r"\$\{([a-zA-Z0-9_]+)\}|\$([a-zA-Z0-9_]+)")

    def expand(val):
        def repl(m):
            k = m.group(1) or m.group(2)
            if k not in env:
                raise AssertionError(f"uninitialized nginx variable read: ${k}")
            return env[k]
        return var_re.sub(repl, val)

    ds = nc.parse(conf_text)
    i = 0
    while i < len(ds):
        d = ds[i]
        if d.name == "set":
            assert d.depth == 0, f"unexpected top-level depth for {d}"
            env[d.args[0].lstrip("$")] = expand(d.args[1])
            i += 1
            continue
        if d.name == "if":
            # Quoted RHS produces 4 tokens: ['($var', '~*', 'pattern', ')'];
            # unquoted RHS produces 3 tokens: ['($var', '=', 'val)'].
            raw = list(d.args)
            assert raw[0].startswith("(") and raw[-1].endswith(")"), raw
            var_name = raw[0][1:].lstrip("$")
            op = raw[1]
            rhs = raw[2] if len(raw) == 4 and raw[3] == ")" else raw[2][:-1]
            if var_name not in env:
                raise AssertionError(f"uninitialized nginx variable in if: ${var_name}")
            lhs = env[var_name]
            if op == "~*":
                matched = bool(re.search(rhs, lhs, re.I))
            elif op == "!~*":
                matched = not bool(re.search(rhs, lhs, re.I))
            elif op == "=":
                matched = lhs == expand(rhs)
            elif op == "!=":
                matched = lhs != expand(rhs)
            else:
                raise AssertionError(f"unsupported op {op}")
            j = i + 1
            while j < len(ds) and ds[j].depth > d.depth:
                body = ds[j]
                if matched:
                    if body.name == "set":
                        env[body.args[0].lstrip("$")] = expand(body.args[1])
                    elif body.name == "return":
                        return int(body.args[0])
                    else:
                        raise AssertionError(f"unexpected body directive: {body}")
                j += 1
            i = j
            continue
        raise AssertionError(f"unexpected top-level directive: {d}")
    return 200


class WooBotConfRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conf_path = REPO / "overrides" / "woo-bot.conf"
        cls.conf_text = cls.conf_path.read_text()

    def test_parses_cleanly_and_uses_only_safe_directives(self):
        ds = nc.parse(self.conf_text)
        self.assertTrue(ds)
        self.assertTrue(all(d.name in ("set", "if", "return") for d in ds), ds)
        self.assertEqual(_eval_woo_bot_conf(self.conf_text), 200)

    def test_rule_1a_blocks_bots_on_cart_and_wishlist_actions(self):
        bots = [
            "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
            "meta-webindexer/1.1",
            "facebookexternalhit/1.1",
            "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            "Mozilla/5.0 (compatible; Bytespider)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            "Mozilla/5.0 (compatible; CustomBot)",
        ]
        actions = [
            "add-to-cart=123",
            "foo=1&add-to-cart=456",
            "remove_item=abc123&_wpnonce=xyz",
            "undo_item=abc123",
            "add_to_wishlist=789",
        ]
        for ua in bots:
            for args in actions:
                for scheme in ("https", "http"):
                    status = _eval_woo_bot_conf(
                        self.conf_text,
                        scheme=scheme,
                        args=args,
                        ua=ua,
                        referer="https://shop.example.com/product/test/",
                        sec_fetch_site="same-origin",
                    )
                    self.assertEqual(status, 403, f"expected 403 for scheme={scheme} ua={ua!r} args={args!r}")

    def test_rule_1a_allows_consumer_devices_and_in_app_browsers(self):
        real_uas = [
            "Mozilla/5.0 (Linux; Android 10; CUBOT P40) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 10; CUBOT) AppleWebKit/537.36 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 baiduboxapp/13.20.0.10 Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 YaBrowser/24.1.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 YandexSearch/24.1",
        ]
        for ua in real_uas:
            status = _eval_woo_bot_conf(
                self.conf_text,
                args="add-to-cart=123",
                ua=ua,
                referer="https://shop.example.com/product/test/",
                sec_fetch_site="same-origin",
            )
            self.assertEqual(status, 200, f"real UA falsely blocked: {ua!r}")

    def test_rule_1b_blocks_aggressive_bots_on_filters_but_allows_googlebot_and_og(self):
        blocked_bots = [
            "meta-externalagent/1.1",
            "meta-webindexer/1.1",
            "facebookexternalhit/1.1",
            "GPTBot/1.2",
            "ClaudeBot/1.0",
            "CCBot/2.0",
            "Bytespider",
            "Amazonbot/0.1",
            "PerplexityBot/1.0",
            "bingbot/2.0",
            "YandexBot/3.0",
            "YandexMobileBot/3.0",
            "Baiduspider/2.0",
            "SemrushBot/7~bl",
        ]
        filter_queries = [
            "filter_color=red",
            "orderby=price&filter_size-eu=42",
            "query_type_color=or&filter_color=red,blue",
            "min_price=100",
            "max_price=500",
            "rating_filter=5",
        ]
        for ua in blocked_bots:
            for args in filter_queries:
                status = _eval_woo_bot_conf(self.conf_text, args=args, ua=ua)
                self.assertEqual(status, 403, f"expected 403 for ua={ua!r} args={args!r}")

        # OpenGraph / social previews on normal product pages stay allowed
        for ua in ("facebookexternalhit/1.1", "meta-externalagent/1.1", "ClaudeBot/1.0"):
            for args in ("", "fbclid=IwAR0abc123", "utm_source=facebook"):
                status = _eval_woo_bot_conf(self.conf_text, args=args, ua=ua)
                self.assertEqual(status, 200, f"expected 200 for ua={ua!r} args={args!r}")

        # Googlebot is allowed on ordinary 1-2 value filtered URLs (for canonical checks)
        gbot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        for args in ("filter_color=red", "min_price=100&max_price=500", "filter_color=red,blue"):
            self.assertEqual(_eval_woo_bot_conf(self.conf_text, args=args, ua=gbot), 200)

    def test_rule_2_blocks_non_browser_https_cart_actions_but_allows_shoppers(self):
        chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"

        # Non-browser HTTPS clients (no Sec-Fetch-Site) with missing or spoofed Referer -> 403
        bad_refs = [
            "",
            "https://evil.example.net/",
            "https://shop.example.com.evil.net/page",
            "https://evil.net/https://shop.example.com/",
            "https://shop.example.com@evil.net/",
            "https://shopXexample.com/product/",  # dot in host must match literally
            "javascript:alert(1)",
        ]
        for ref in bad_refs:
            for args in ("add-to-cart=99", "remove_item=abc", "add_to_wishlist=42"):
                status = _eval_woo_bot_conf(
                    self.conf_text, scheme="https", host="shop.example.com",
                    args=args, ua=chrome, referer=ref,
                )
                self.assertEqual(status, 403, f"expected 403 for ref={ref!r} args={args!r}")

        # Plain HTTP browser clicks omit Sec-Fetch-Site and must pass through to HTTP->HTTPS redirect
        self.assertEqual(
            _eval_woo_bot_conf(
                self.conf_text, scheme="http", args="add-to-cart=99", ua=chrome,
                referer="https://newsletter.example.net/",
            ),
            200,
        )

        # Older browsers without Sec-Fetch-Site clicking on-site (same-host Referer) -> 200
        good_cases = [
            ("shop.example.com",     "https://shop.example.com/product/a/"),
            ("shop.example.com",     "https://shop.example.com"),
            ("shop.example.com",     "https://www.shop.example.com/product/a/"),
            ("www.shop.example.com", "https://www.shop.example.com/product/a/"),
            ("www.shop.example.com", "https://shop.example.com/product/a/"),
            ("shop.example.com",     "http://shop.example.com:8080/cart/"),
        ]
        for host, ref in good_cases:
            status = _eval_woo_bot_conf(
                self.conf_text, host=host, args="add-to-cart=99", ua=chrome, referer=ref,
            )
            self.assertEqual(status, 200, f"expected 200 for host={host!r} ref={ref!r}")

        # Modern HTTPS browsers arriving from storefront, email, ads, QR, bookmarks, sister subdomain -> 200
        for sfs in ("same-origin", "same-site", "cross-site", "none"):
            self.assertEqual(
                _eval_woo_bot_conf(
                    self.conf_text, args="add-to-cart=99", ua=chrome,
                    referer="", sec_fetch_site=sfs,
                ),
                200,
                f"expected 200 for Sec-Fetch-Site: {sfs}",
            )

        # AdsBot-Google sends no Sec-Fetch-Site or Referer, so Rule 2 blocks ?add-to-cart= (documented)
        self.assertEqual(
            _eval_woo_bot_conf(
                self.conf_text, args="add-to-cart=99",
                ua="AdsBot-Google (+http://www.google.com/adsbot.html)",
            ),
            403,
        )

    def test_rule_3_blocks_non_browser_https_combinatorial_traps_but_allows_guests(self):
        chrome = "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36"

        # Non-browser HTTPS scraper (no Sec-Fetch-Site, no same-host Referer) on 3+ values -> 403
        blocked = [
            "filter_color=red,blue,green",
            "filter_color=red%2Cblue%2Cgreen",
            "filter_color=red%2cblue%2cgreen",
            "orderby=price&filter_size-eu=s,m,l,xl",
            "filter_brand=a,b%2Cc&min_price=10",
        ]
        for args in blocked:
            self.assertEqual(
                _eval_woo_bot_conf(self.conf_text, scheme="https", args=args, ua=chrome), 403, args,
            )

        # Plain HTTP request passes through to HTTP->HTTPS redirect
        self.assertEqual(
            _eval_woo_bot_conf(
                self.conf_text, scheme="http", args="filter_size=s,m,l&query_type_size=or", ua=chrome,
            ),
            200,
        )

        # Real guest shopper selecting 3+ values in WooCommerce layered navigation -> 200
        self.assertEqual(
            _eval_woo_bot_conf(
                self.conf_text,
                args="filter_size=s,m,l&query_type_size=or",
                ua=chrome,
                sec_fetch_site="same-origin",
            ),
            200,
        )
        # Older browser without Sec-Fetch-Site navigating on-site -> 200
        self.assertEqual(
            _eval_woo_bot_conf(
                self.conf_text,
                args="filter_size=s,m,l&query_type_size=or",
                ua=chrome,
                referer="https://shop.example.com/shop/",
            ),
            200,
        )

        # 1 or 2 values per filter, or non-Woo filter params -> 200 even without headers
        allowed = [
            "filter_color=red",
            "filter_color=red,blue",
            "filter_color=red%2Cblue",
            "filter_color=red,blue&filter_size=m,l&filter_brand=x,y",
            "my_filter_color=a,b,c",
        ]
        for args in allowed:
            self.assertEqual(
                _eval_woo_bot_conf(self.conf_text, args=args, ua=chrome), 200, args,
            )


class WooBotIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        names = (
            "SITES_DIR", "CACHE_EXCLUDES_DIR", "REDIRECTS_DIR", "OVERRIDES",
            "NGINX_CONF", "NGINX_LOCK", "FAILED_STATE", "OVERRIDES_STATE",
            "BACKUP_BASE", "WWW_DIR", "_test_nginx", "_reload_nginx",
            "log_preflight_ok", "_cacheexclude_mod", "_skip_logged",
            "WOO_DETECT_MAX_ENTRIES",
        )
        saved = {k: getattr(ngx, k) for k in names}
        self.addCleanup(lambda: [setattr(ngx, k, v) for k, v in saved.items()])

        self.sites = self.tmp / "sites-enabled"
        self.ce = self.tmp / "cache-excludes"
        self.overrides = self.tmp / "overrides"
        self.www = self.tmp / "www"
        for d in (self.sites, self.ce, self.overrides, self.www, self.tmp / "redirects"):
            d.mkdir()
        shutil.copy2(REPO / "overrides" / "woo-bot.conf", self.overrides / "woo-bot.conf")

        # Isolate nginxcacheexclude completely so cleanup() never touches /opt/...
        ce_mod = load("nginxcacheexclude")
        ce_mod.CACHE_EXCLUDES_DIR = self.ce
        ce_mod.SITES_DIR = self.sites
        ngx._cacheexclude_mod = ce_mod

        ngx.SITES_DIR = self.sites
        ngx.CACHE_EXCLUDES_DIR = self.ce
        ngx.REDIRECTS_DIR = self.tmp / "redirects"
        ngx.OVERRIDES = self.overrides
        ngx.WWW_DIR = self.www
        ngx.NGINX_CONF = self.tmp / "nginx.conf"
        ngx.NGINX_LOCK = self.tmp / "nginx.lock"
        ngx.FAILED_STATE = self.tmp / "failed-run"
        ngx.OVERRIDES_STATE = self.tmp / "overrides-loaded"
        ngx.BACKUP_BASE = self.tmp / "backups"
        ngx.NGINX_CONF.write_text("http { include sites-enabled/*; }\n")
        ngx._skip_logged = None
        ngx._test_nginx = lambda: (True, "")
        ngx._reload_nginx = lambda logger: True
        ngx.log_preflight_ok = lambda logger, action: True

    def _make_vhost(self, domain, docroot, extra_top=""):
        cf = self.sites / f"{domain}.conf"
        cf.write_text(
            "server {\n"
            f"    server_name {domain};\n"
            f'    root "{docroot}";\n'
            f"{extra_top}"
            f"    include vhost_includes/{domain}.conf;\n"
            "}\n"
        )
        return cf

    def _make_wp(self, path, woocommerce=False):
        path.mkdir(parents=True, exist_ok=True)
        (path / "wp-load.php").write_text("<?php\n")
        if woocommerce:
            wc = path / "wp-content" / "plugins" / "woocommerce"
            wc.mkdir(parents=True, exist_ok=True)
            (wc / "woocommerce.php").write_text("<?php\n")
        return path

    def test_only_woocommerce_vhosts_get_include(self):
        woo_root   = self._make_wp(self.www / "shop" / "public_html", woocommerce=True)
        sub_root   = self.www / "subshop" / "public_html"
        self._make_wp(sub_root / "store", woocommerce=True)
        wp_root    = self._make_wp(self.www / "blog" / "public_html", woocommerce=False)
        static_dir = self.www / "static" / "public_html"
        static_dir.mkdir(parents=True)
        allow_root = self._make_wp(self.www / "allowed" / "public_html", woocommerce=True)

        cf_woo     = self._make_vhost("shop.example.com", woo_root)
        cf_sub     = self._make_vhost("sub.example.com", sub_root)
        cf_wp      = self._make_vhost("blog.example.com", wp_root)
        cf_static  = self._make_vhost("static.example.com", static_dir)
        cf_missing = self._make_vhost("missing.example.com", self.www / "does-not-exist")
        cf_allow   = self._make_vhost("allow.example.com", allow_root)
        cf_default = self._make_vhost("default", woo_root)

        cfg = {"nginx": {"features": {
            "woo_bot_protection": True,
            "woo_bot_allow_domains": ["Allow.Example.com"],
        }}}
        inc = f"include {self.overrides}/woo-bot.conf;"

        self.assertTrue(ngx.apply_include_features(cfg, LOG))
        self.assertIn(inc, cf_woo.read_text())
        self.assertIn(inc, cf_sub.read_text())
        self.assertNotIn(inc, cf_wp.read_text())
        self.assertNotIn(inc, cf_static.read_text())
        self.assertNotIn(inc, cf_missing.read_text())
        self.assertNotIn(inc, cf_allow.read_text())
        self.assertNotIn(inc, cf_default.read_text())

        # Second run is idempotent
        self.assertFalse(ngx.apply_include_features(cfg, LOG))

        # Disabling strips the include cleanly
        cfg_off = {"nginx": {"features": {"woo_bot_protection": False}}}
        self.assertTrue(ngx.apply_include_features(cfg_off, LOG))
        self.assertNotIn(inc, cf_woo.read_text())
        self.assertNotIn(inc, cf_sub.read_text())
        self.assertFalse(ngx.apply_include_features(cfg_off, LOG))

    def test_symlinks_ancestors_outside_www_non_regular_and_scan_cap(self):
        outside = self._make_wp(self.tmp / "outside-woo", woocommerce=True)
        outside_parent = self.tmp / "outside-parent"
        self._make_wp(outside_parent / "public_html", woocommerce=True)

        # 1. Docroot outside WWW_DIR is refused
        cf_outside = self._make_vhost("outside.example.com", outside)

        # 2. Symlinked docroot is refused
        sym_doc = self.www / "sym-doc"
        sym_doc.symlink_to(outside)
        cf_sym_doc = self._make_vhost("symdoc.example.com", sym_doc)

        # 3. Symlinked ancestor directory above docroot is refused
        sym_anc_tenant = self.www / "sym-anc"
        sym_anc_tenant.mkdir()
        (sym_anc_tenant / "linked").symlink_to(outside_parent)
        cf_sym_anc = self._make_vhost("symanc.example.com", sym_anc_tenant / "linked" / "public_html")

        # 4. Symlinked immediate subdirectory is refused
        sym_sub_root = self.www / "sym-sub" / "public_html"
        sym_sub_root.mkdir(parents=True)
        (sym_sub_root / "shop").symlink_to(outside)
        cf_sym_sub = self._make_vhost("symsub.example.com", sym_sub_root)

        # 5. Symlinked woocommerce.php or directory named woocommerce.php is refused
        sym_file_root = self._make_wp(self.www / "sym-file" / "public_html", woocommerce=False)
        wc_dir = sym_file_root / "wp-content" / "plugins" / "woocommerce"
        wc_dir.mkdir(parents=True)
        (wc_dir / "woocommerce.php").symlink_to(outside / "wp-content/plugins/woocommerce/woocommerce.php")
        cf_sym_file = self._make_vhost("symfile.example.com", sym_file_root)

        dir_marker_root = self._make_wp(self.www / "dir-marker" / "public_html", woocommerce=False)
        (dir_marker_root / "wp-content" / "plugins" / "woocommerce" / "woocommerce.php").mkdir(parents=True)
        cf_dir_marker = self._make_vhost("dirmarker.example.com", dir_marker_root)

        # 6. Scan cap stops subdirectory scanning deterministically while checking docroot first
        wide_sub_root = self.www / "wide-sub" / "public_html"
        self._make_wp(wide_sub_root / "store", woocommerce=True)
        cf_wide_sub = self._make_vhost("widesub.example.com", wide_sub_root)

        wide_docroot = self._make_wp(self.www / "wide-doc" / "public_html", woocommerce=True)
        for i in range(5):
            (wide_docroot / f"d{i:02d}").mkdir()
        cf_wide_doc = self._make_vhost("widedoc.example.com", wide_docroot)

        cfg = {"nginx": {"features": {"woo_bot_protection": True}}}
        inc = f"include {self.overrides}/woo-bot.conf;"

        # With cap=0: docroot itself is still detected, subdirectory scan stops immediately
        ngx.WOO_DETECT_MAX_ENTRIES = 0
        ngx.apply_include_features(cfg, LOG)

        for cf in (cf_outside, cf_sym_doc, cf_sym_anc, cf_sym_sub, cf_sym_file, cf_dir_marker):
            self.assertNotIn(inc, cf.read_text(), cf.name)
        self.assertIn(inc, cf_wide_doc.read_text())
        self.assertNotIn(inc, cf_wide_sub.read_text(), "scan cap failed to stop child scan")

        # Raising the cap lets the subdirectory install be picked up while symlinks stay refused
        ngx.WOO_DETECT_MAX_ENTRIES = 500
        ngx.apply_include_features(cfg, LOG)
        self.assertIn(inc, cf_wide_sub.read_text())
        for cf in (cf_outside, cf_sym_doc, cf_sym_anc, cf_sym_sub, cf_sym_file, cf_dir_marker):
            self.assertNotIn(inc, cf.read_text(), f"{cf.name} should stay excluded with cap=500")

    def test_split_http_and_https_server_blocks_both_protected(self):
        woo_root = self._make_wp(self.www / "split" / "public_html", woocommerce=True)
        inc = f"include {self.overrides}/woo-bot.conf;"

        # Case 1: HTTP redirect-only block (no root) + HTTPS serving block (with root)
        cf_redir = self.sites / "redir.example.com.conf"
        cf_redir.write_text(
            "server {\n"
            "    listen 80;\n"
            "    server_name redir.example.com;\n"
            "    return 301 https://$host$request_uri;\n"
            "}\n"
            "server {\n"
            "    listen 443 ssl;\n"
            "    server_name redir.example.com;\n"
            f'    root "{woo_root}";\n'
            "    include vhost_includes/redir.example.com.conf;\n"
            "}\n"
        )

        # Case 2: Both HTTP and HTTPS serve the shop; HTTP already has the include, HTTPS lacks it
        cf_dual = self.sites / "dual.example.com.conf"
        cf_dual.write_text(
            "server {\n"
            "    listen 80;\n"
            "    server_name dual.example.com;\n"
            f'    root "{woo_root}";\n'
            "    include vhost_includes/dual.example.com.conf;\n"
            f"    {inc}\n"
            "}\n"
            "server {\n"
            "    listen 443 ssl;\n"
            "    server_name dual.example.com;\n"
            f'    root "{woo_root}";\n'
            "    location /sub { include vhost_includes/ignored-in-location.conf; }\n"
            "    include vhost_includes/dual.example.com.conf;\n"
            "}\n"
        )

        cfg = {"nginx": {"features": {"woo_bot_protection": True}}}
        self.assertTrue(ngx.apply_include_features(cfg, LOG))

        redir_txt = cf_redir.read_text()
        self.assertEqual(redir_txt.count(inc), 1)
        self.assertGreater(redir_txt.index(inc), redir_txt.index("listen 443 ssl;"))

        dual_txt = cf_dual.read_text()
        self.assertEqual(dual_txt.count(inc), 2)
        https_part = dual_txt.split("listen 443 ssl;", 1)[1]
        self.assertIn(inc, https_part)
        self.assertGreater(
            https_part.index(inc),
            https_part.index("include vhost_includes/dual.example.com.conf;"),
        )

        # Idempotent on second run
        self.assertFalse(ngx.apply_include_features(cfg, LOG))

        # Disabling removes the include from every server block
        self.assertTrue(ngx.apply_include_features({"nginx": {"features": {"woo_bot_protection": False}}}, LOG))
        self.assertNotIn(inc, cf_redir.read_text())
        self.assertNotIn(inc, cf_dual.read_text())

    def test_parser_offset_edge_cases_multiline_shared_lines_and_location_root(self):
        woo_root = self._make_wp(self.www / "edge" / "public_html", woocommerce=True)
        assets_dir = self.www / "edge" / "assets"
        assets_dir.mkdir(parents=True)
        inc = f"include {self.overrides}/woo-bot.conf;"
        hard_inc = f"include {self.overrides}/hardening.conf;"
        (self.overrides / "hardening.conf").write_text("server_tokens off;\n")

        # 1. Multiline vhost_includes + location root before server root + shared-line directive
        cf_ml = self.sites / "multiline.example.com.conf"
        cf_ml.write_text(
            "server {\n"
            "    listen 443 ssl;\n"
            f'    location /assets {{ root "{assets_dir}"; }}\n'
            f'    root "{woo_root}";\n'
            "    include\n"
            "        vhost_includes/multiline.example.com.conf;\n"
            f"    set $keep 1; {inc}\n"
            "}\n"
        )
        # Reconcile with woo_bot disabled -> removes ONLY woo-bot, keeps `set $keep 1;`
        self.assertTrue(ngx.apply_include_features({"nginx": {"features": {"woo_bot_protection": False}}}, LOG))
        after_rm = cf_ml.read_text()
        self.assertNotIn(inc, after_rm)
        self.assertIn("set $keep 1;", after_rm)
        nc.parse(after_rm)

        # Re-enable -> detects server root (ignoring location /assets root), inserts AFTER multiline directive
        self.assertTrue(ngx.apply_include_features({"nginx": {"features": {"woo_bot_protection": True}}}, LOG))
        after_add = cf_ml.read_text()
        self.assertIn(inc, after_add)
        self.assertIn("include\n        vhost_includes/multiline.example.com.conf;\n", after_add)
        self.assertGreater(after_add.index(inc), after_add.index("vhost_includes/multiline.example.com.conf;"))
        ds = nc.parse(after_add)
        self.assertTrue(any(d.name == "include" and d.ctx == ("server",) and d.args == [f"{self.overrides}/woo-bot.conf"] for d in ds))

        # 2. Single-line server block and shared closing brace with next server block (fallback insertion)
        cf_compact = self.sites / "compact.example.com.conf"
        cf_compact.write_text(
            "server { listen 80; location / { return 301 https://$host$request_uri; } } "
            f'server {{ listen 443 ssl; root "{woo_root}"; location /a {{ return 200; }} }}\n'
        )
        cfg_both = {"nginx": {"features": {"woo_bot_protection": True, "server_hardening": True}}}
        self.assertTrue(ngx.apply_include_features(cfg_both, LOG))
        compact_txt = cf_compact.read_text()
        ds_c = nc.parse(compact_txt)
        # Hardening landed in BOTH server blocks at server context (never inside location or http)
        hard_ctx = [d.ctx for d in ds_c if d.name == "include" and d.args == [f"{self.overrides}/hardening.conf"]]
        woo_ctx  = [d.ctx for d in ds_c if d.name == "include" and d.args == [f"{self.overrides}/woo-bot.conf"]]
        self.assertEqual(hard_ctx, [("server",), ("server",)])
        self.assertEqual(woo_ctx, [("server",)])
        # Idempotent and cleanly removable
        self.assertFalse(ngx.apply_include_features(cfg_both, LOG))
        self.assertTrue(ngx.apply_include_features({"nginx": {"features": {}}}, LOG))
        self.assertNotIn(inc, cf_compact.read_text())
        self.assertNotIn(hard_inc, cf_compact.read_text())
        nc.parse(cf_compact.read_text())

    def test_legacy_path_cleaned_and_commented_vhost_include_skipped(self):
        woo_root = self._make_wp(self.www / "shop" / "public_html", woocommerce=True)
        cf = self._make_vhost(
            "shop.example.com",
            woo_root,
            extra_top=(
                "    # include vhost_includes/commented.conf;\n"
                "    include /opt/nginxtune-enhance/overrides/woo-bot.conf;\n"
                '    include "/etc/nginx/local/hardening.conf";\n'
            ),
        )
        cfg = {"nginx": {"features": {"woo_bot_protection": True}}}
        inc = f"include {self.overrides}/woo-bot.conf;"

        self.assertTrue(ngx.apply_include_features(cfg, LOG))
        text = cf.read_text()
        self.assertNotIn("/opt/nginxtune-enhance/overrides/woo-bot.conf", text)
        self.assertIn('include "/etc/nginx/local/hardening.conf";', text)
        self.assertIn(inc, text)
        # Placed after the real vhost_includes line, not after the comment
        self.assertGreater(text.index(inc), text.index("include vhost_includes/shop.example.com.conf;"))

        # Disabling all features still preserves the admin's custom hardening.conf include
        self.assertTrue(ngx.apply_include_features({"nginx": {"features": {}}}, LOG))
        self.assertIn('include "/etc/nginx/local/hardening.conf";', cf.read_text())

    def test_nested_location_cache_exclude_cleaned_when_disabled(self):
        woo_root = self._make_wp(self.www / "nested" / "public_html", woocommerce=True)
        ce_inc = f"include {self.ce}/nested.example.com.conf;"
        (self.ce / "nested.example.com.conf").write_text("# rules\n")
        cf = self.sites / "nested.example.com.conf"
        cf.write_text(
            "server {\n"
            "    listen 443 ssl;\n"
            f'    root "{woo_root}";\n'
            "    location / {\n"
            "        include vhost_includes/nested.example.com.conf;\n"
            f"        {ce_inc}\n"
            "    }\n"
            "}\n"
        )
        self.assertTrue(ngx.apply_include_features({"nginx-cacheexclude": {"enabled": False}}, LOG))
        self.assertNotIn(ce_inc, cf.read_text())
        nc.parse(cf.read_text())

    def test_string_allowlist_ignored_safely(self):
        woo_root = self._make_wp(self.www / "shop" / "public_html", woocommerce=True)
        cf = self._make_vhost("shop.example.com", woo_root)
        cfg = {"nginx": {"features": {
            "woo_bot_protection": True,
            "woo_bot_allow_domains": "shop.example.com",  # misconfigured string
        }}}
        self.assertTrue(ngx.apply_include_features(cfg, LOG))
        self.assertIn(f"include {self.overrides}/woo-bot.conf;", cf.read_text())

    def test_cleanup_removes_woo_bot_include_and_temp_cache_excludes_only(self):
        woo_root = self._make_wp(self.www / "shop" / "public_html", woocommerce=True)
        cf_woo = self._make_vhost("shop.example.com", woo_root)
        temp_ce = self.ce / "shop.example.com.conf"
        temp_ce.write_text("# temp cache exclude\n")
        inc = f"include {self.overrides}/woo-bot.conf;"

        cfg = {"nginx": {"features": {"woo_bot_protection": True}}}
        ngx.apply_include_features(cfg, LOG)
        self.assertIn(inc, cf_woo.read_text())

        ngx.cleanup(LOG)
        self.assertNotIn(inc, cf_woo.read_text())
        self.assertFalse(temp_ce.exists())

    def test_failed_nginx_test_undoes_woo_bot_include(self):
        woo_root = self._make_wp(self.www / "shop" / "public_html", woocommerce=True)
        cf_woo = self._make_vhost("shop.example.com", woo_root)
        original = cf_woo.read_text()
        inc = f"include {self.overrides}/woo-bot.conf;"
        seen_during_test = []

        def fail_test():
            seen_during_test.append(inc in cf_woo.read_text())
            return (False, "nginx: [emerg] test failure")

        ngx._test_nginx = fail_test
        ngx.run({"nginx": {"features": {"woo_bot_protection": True}}}, LOG)
        self.assertEqual(seen_during_test, [True], "include was not present when nginx -t ran")
        self.assertEqual(cf_woo.read_text(), original)


@unittest.skipUnless(shutil.which("nginx") and shutil.which("openssl"), "nginx and openssl required")
class WooBotLiveNginxTests(unittest.TestCase):
    """End-to-end HTTP + HTTPS smoke tests against a real local nginx binary."""

    @staticmethod
    def _free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    @staticmethod
    def _wait_ready(port, proc, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    def test_real_nginx_pcre2_http_and_https_matrix(self):
        tmp = Path(tempfile.mkdtemp(prefix="wt-woobot-live-")).resolve()
        self.addCleanup(shutil.rmtree, tmp, True)
        os.chmod(tmp, 0o755)
        body_tmp = tmp / "tmp"
        body_tmp.mkdir()
        os.chmod(body_tmp, 0o777)
        docroot = tmp / "public_html"
        docroot.mkdir()
        os.chmod(docroot, 0o755)
        (docroot / "index.php").write_text("<?php\n")
        err_log = tmp / "error.log"
        pid_file = tmp / "nginx.pid"
        woo_conf = REPO / "overrides" / "woo-bot.conf"
        main_conf = tmp / "nginx.conf"
        cert = tmp / "cert.pem"
        key = tmp / "key.pem"

        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=shop.example.com"],
            check=True, capture_output=True, text=True,
        )
        os.chmod(cert, 0o644)
        os.chmod(key, 0o644)

        user_line = ""
        if os.geteuid() == 0:
            for candidate in ("www-data", "nobody", "nginx"):
                try:
                    pwd.getpwnam(candidate)
                    user_line = f"user {candidate};\n"
                    break
                except KeyError:
                    continue

        http_port = self._free_port()
        https_port = self._free_port()

        main_conf.write_text(
            f"{user_line}"
            f"worker_processes 1;\n"
            f"pid {pid_file};\n"
            f"error_log {err_log} warn;\n"
            f"events {{ worker_connections 64; }}\n"
            f"http {{\n"
            f"    access_log off;\n"
            f"    client_body_temp_path {body_tmp}/body;\n"
            f"    proxy_temp_path {body_tmp}/proxy;\n"
            f"    fastcgi_temp_path {body_tmp}/fastcgi;\n"
            f"    uwsgi_temp_path {body_tmp}/uwsgi;\n"
            f"    scgi_temp_path {body_tmp}/scgi;\n"
            f"    server {{\n"
            f"        listen 127.0.0.1:{http_port};\n"
            f"        listen 127.0.0.1:{https_port} ssl;\n"
            f"        ssl_certificate {cert};\n"
            f"        ssl_certificate_key {key};\n"
            f"        server_name _;\n"
            f"        root {docroot};\n"
            f"        index index.php;\n"
            f"        set $skip_cache 0;\n"
            f"        include {woo_conf};\n"
            f"        if ($scheme = http) {{ return 301 https://$host$request_uri; }}\n"
            f"        if ($request_uri ~* \"/(cart|checkout)(/|$|\\?)\") {{\n"
            f"            set $skip_cache 1;\n"
            f"        }}\n"
            f"        location / {{ try_files $uri $uri/ /index.php?$args; }}\n"
            f"        location = /index.php {{ return 200 'PHP skip=$skip_cache\\n'; }}\n"
            f"    }}\n"
            f"}}\n"
        )
        t = subprocess.run(["nginx", "-t", "-e", str(err_log), "-c", str(main_conf)],
                           capture_output=True, text=True)
        self.assertEqual(t.returncode, 0, t.stderr)

        proc = subprocess.Popen(
            ["nginx", "-e", str(err_log), "-g", "daemon off;", "-c", str(main_conf)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        def _stop():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            for pipe in (proc.stdout, proc.stderr):
                if pipe:
                    pipe.close()

        self.addCleanup(_stop)
        if not self._wait_ready(https_port, proc):
            stderr = proc.stderr.read() if proc.poll() is not None else "timed out waiting for listen socket"
            self.fail(f"nginx failed to start: {stderr}")

        chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
        gbot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        cubot1 = "Mozilla/5.0 (Linux; Android 10; CUBOT P40) AppleWebKit/537.36 Mobile Safari/537.36"
        cubot2 = "Mozilla/5.0 (Linux; Android 10; CUBOT) AppleWebKit/537.36 Mobile Safari/537.36"
        tls_ctx = ssl._create_unverified_context()

        cases = [
            # (scheme, desc, path, headers, expected_status, expected_body_or_location)
            ("https", "normal homepage cacheable", "/", {"Host": "shop.example.com", "User-Agent": chrome}, 200, "PHP skip=0"),
            ("https", "cart page sets skip_cache=1", "/cart/", {"Host": "shop.example.com", "User-Agent": chrome}, 200, "PHP skip=1"),
            ("https", "OG preview facebook", "/produs/x/?fbclid=IwAR0123", {"Host": "shop.example.com", "User-Agent": "facebookexternalhit/1.1"}, 200, "PHP skip=0"),
            ("https", "meta bot add-to-cart spoofed ref+sfs", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": "meta-externalagent/1.1", "Referer": "https://shop.example.com/", "Sec-Fetch-Site": "same-origin"}, 403, None),
            ("http",  "meta bot add-to-cart over plain HTTP blocked before redirect", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": "meta-externalagent/1.1"}, 403, None),
            ("https", "googlebot add-to-cart", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": gbot}, 403, None),
            ("https", "CUBOT P40 add-to-cart", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": cubot1, "Sec-Fetch-Site": "same-origin"}, 200, "PHP skip=0"),
            ("https", "CUBOT) add-to-cart", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": cubot2, "Sec-Fetch-Site": "same-origin"}, 200, "PHP skip=0"),
            ("https", "baiduboxapp add-to-cart", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": "Mozilla/5.0 baiduboxapp/13.20", "Sec-Fetch-Site": "same-origin"}, 200, "PHP skip=0"),
            ("https", "YaBrowser add-to-cart", "/?add-to-cart=123", {"Host": "shop.example.com", "User-Agent": "Mozilla/5.0 YaBrowser/24.1", "Sec-Fetch-Site": "same-origin"}, 200, "PHP skip=0"),
            ("https", "meta bot filter_color", "/shop/?filter_color=red", {"Host": "shop.example.com", "User-Agent": "meta-webindexer/1.1"}, 403, None),
            ("https", "ClaudeBot min_price", "/shop/?min_price=100", {"Host": "shop.example.com", "User-Agent": "ClaudeBot/1.0"}, 403, None),
            ("https", "Baiduspider filter_size", "/shop/?filter_size=xl", {"Host": "shop.example.com", "User-Agent": "Baiduspider/2.0"}, 403, None),
            ("https", "YandexBot max_price", "/shop/?max_price=500", {"Host": "shop.example.com", "User-Agent": "YandexBot/3.0"}, 403, None),
            ("https", "Googlebot 1-2 filter allowed", "/shop/?filter_color=red,blue", {"Host": "shop.example.com", "User-Agent": gbot}, 200, "PHP skip=0"),
            ("https", "non-browser add-to-cart no referer", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome}, 403, None),
            ("https", "non-browser add-to-cart external referer", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://evil.example.net/"}, 403, None),
            ("https", "non-browser add-to-cart prefix-spoof", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://shop.example.com.evil.net/"}, 403, None),
            ("https", "non-browser add-to-cart dot-spoof", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://shopXexample.com/"}, 403, None),
            ("https", "legacy browser add-to-cart same-host ref", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://shop.example.com/produs/a/"}, 200, "PHP skip=0"),
            ("https", "legacy browser add-to-cart apex->www", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://www.shop.example.com/produs/a/"}, 200, "PHP skip=0"),
            ("https", "modern browser email link (none)", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Sec-Fetch-Site": "none"}, 200, "PHP skip=0"),
            ("https", "modern browser ad link (cross-site)", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Sec-Fetch-Site": "cross-site"}, 200, "PHP skip=0"),
            ("https", "modern browser subdomain (same-site)", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Sec-Fetch-Site": "same-site"}, 200, "PHP skip=0"),
            ("http",  "plain HTTP shopper add-to-cart reaches 301 redirect", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://newsletter.example.net/"}, 301, "https://shop.example.com/?add-to-cart=99"),
            ("https", "AdsBot-Google on add-to-cart blocked by rule 2", "/?add-to-cart=99", {"Host": "shop.example.com", "User-Agent": "AdsBot-Google (+http://www.google.com/adsbot.html)"}, 403, None),
            ("https", "guest browser 3-value OR filter allowed", "/shop/?filter_size=s,m,l&query_type_size=or", {"Host": "shop.example.com", "User-Agent": chrome, "Sec-Fetch-Site": "same-origin"}, 200, "PHP skip=0"),
            ("https", "legacy browser 3-value OR filter same-host ref", "/shop/?filter_size=s,m,l&query_type_size=or", {"Host": "shop.example.com", "User-Agent": chrome, "Referer": "https://shop.example.com/shop/"}, 200, "PHP skip=0"),
            ("http",  "plain HTTP 3-value filter reaches 301 redirect", "/shop/?filter_size=s,m,l&query_type_size=or", {"Host": "shop.example.com", "User-Agent": chrome}, 301, "https://shop.example.com/shop/?filter_size=s,m,l&query_type_size=or"),
            ("https", "non-browser 3-value filter comma blocked", "/shop/?filter_color=red,blue,green", {"Host": "shop.example.com", "User-Agent": chrome}, 403, None),
            ("https", "non-browser 3-value filter %2C blocked", "/shop/?filter_color=red%2Cblue%2Cgreen", {"Host": "shop.example.com", "User-Agent": chrome}, 403, None),
            ("https", "wc-ajax add_to_cart allowed", "/?wc-ajax=add_to_cart", {"Host": "shop.example.com", "User-Agent": chrome}, 200, "PHP skip=0"),
            ("https", "wc-api payment callback allowed", "/?wc-api=WC_Gateway_Netopia", {"Host": "shop.example.com", "User-Agent": "NetopiaCallback/1.0"}, 200, "PHP skip=0"),
        ]

        for scheme, desc, path, hdrs, expected, check in cases:
            if scheme == "https":
                conn = http.client.HTTPSConnection("127.0.0.1", https_port, timeout=5, context=tls_ctx)
            else:
                conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "replace").strip()
            loc = resp.getheader("Location")
            conn.close()
            self.assertEqual(resp.status, expected, f"{desc}: got {resp.status}, want {expected}")
            if expected == 301:
                self.assertEqual(loc, check, f"{desc}: unexpected Location {loc!r}")
            elif check is not None:
                self.assertEqual(body, check, f"{desc}: unexpected body {body!r}")

        self.assertEqual(err_log.read_text().strip(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
