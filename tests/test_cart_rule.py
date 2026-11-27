#!/usr/bin/env python3
"""
The WooCommerce URI rule in nginxcacheexclude must bypass the cache for the
store, cart, checkout and account pages (and their sub-pages, numbered copies
and CartFlows steps), but not for ordinary pages whose slug merely starts with
the same letters, such as /carti/ or /cartea-... in a Romanian bookshop.

    python3 -m unittest discover -s tests -v
"""

import importlib.machinery
import importlib.util
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load(name):
    loader = importlib.machinery.SourceFileLoader(name, str(REPO / "modules" / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


ce = load("nginxcacheexclude")


def _uri_rule():
    """The single $request_uri regex among the WooCommerce rules, compiled like nginx's ~*."""
    found = [m.group(1) for line in ce.WOOCOMMERCE_RULES
             for m in [re.match(r'if \(\$request_uri ~\* "([^"]+)"\) \{$', line)] if m]
    assert len(found) == 1, found
    return re.compile(found[0], re.I)


BYPASSED = [
    "/cart", "/cart/", "/cart/?remove_item=abc", "/Cart/", "/cart-2/",
    "/checkout/", "/checkout/order-received/123/", "/checkout/order-pay/5/?pay_for_order=true",
    "/my-account/", "/my-account/orders/", "/my-account-2/",
    "/store/", "/store", "/addons/", "/en/cart/", "/shop/checkout/",
    "/store-checkout-thank-you-02/",          # CartFlows thank-you page
    "/checkout-simulation/",
    "/cartflows_step/oferta/", "/cartflows_step/oferta/?wcf-key=x",
]

CACHEABLE = [
    "/", "/carti/", "/categorie/carti/povesti-pentru-copii/", "/carti-publicate/",
    "/cartea-wow/", "/produs/cartea-de-logopedie/", "/carte-de-logopedie-2/",
    "/portfolio-item/carte-8/", "/cartron-caramel-liqueur-0-7l/", "/brand/cartron",
    "/storefront/", "/stores", "/storeman/", "/addonsx/", "/checkouts-guide/",
    "/my-accountant/", "/blog/how-to-cart/",
]


class CartRuleTests(unittest.TestCase):
    def test_store_pages_bypass_cache(self):
        rule = _uri_rule()
        missed = [u for u in BYPASSED if not rule.search(u)]
        self.assertEqual(missed, [])

    def test_ordinary_pages_stay_cacheable(self):
        rule = _uri_rule()
        caught = [u for u in CACHEABLE if rule.search(u)]
        self.assertEqual(caught, [])

    def test_rule_is_nginx_safe(self):
        # A quoted nginx string: no ";", "{", "}" or "\" that the config parser could
        # read differently from PCRE.
        rule = _uri_rule().pattern
        self.assertFalse(set(rule) & set(';{}\\'), rule)


if __name__ == "__main__":
    unittest.main()
