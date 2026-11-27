#!/usr/bin/env python3
"""
Regression tests for the review findings fixed together:

- a failed run is undone exactly (cache-exclude files included), and its undo
  does not start a restore -> inotify -> run -> fail loop;
- runs, cleanup and nginxredirects never overlap (shared flock);
- config files are written atomically;
- cms_protection / xmlrpc_protection rules cover the paths they should and
  leave ordinary requests alone.

    python3 -m unittest discover -s tests -v
"""

import importlib.machinery
import importlib.util
import logging
import os
import re
import shutil
import stat
import tempfile
import threading
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
LOG = logging.getLogger("test-review")
LOG.addHandler(logging.NullHandler())

APPLY_STEPS = ("apply_nginx_conf", "apply_http3_enable", "apply_quic_gso_enable",
               "_apply_cache_excludes", "apply_include_features", "apply_logging_features",
               "apply_fastcgi_cache_settings", "apply_client_max_body_size")


class RunHarness(unittest.TestCase):
    """run() on a temporary tree, with nginx -t / reload simulated."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        names = ("NGINX_CONF", "NGINX_LOCK", "FAILED_STATE", "OVERRIDES_STATE", "SITES_DIR", "CACHE_EXCLUDES_DIR",
                 "REDIRECTS_DIR", "OVERRIDES", "BACKUP_BASE", "_test_nginx", "_reload_nginx",
                 "log_preflight_ok", "_cacheexclude_mod", "_skip_logged") + APPLY_STEPS
        saved = {k: getattr(ngx, k) for k in names}
        self.addCleanup(lambda: [setattr(ngx, k, v) for k, v in saved.items()])
        self.sites = self.tmp / "sites-enabled"
        self.ce    = self.tmp / "cache-excludes"
        for d in (self.sites, self.ce, self.tmp / "redirects", self.tmp / "overrides"):
            d.mkdir()
        ngx.SITES_DIR, ngx.CACHE_EXCLUDES_DIR = self.sites, self.ce
        ngx.REDIRECTS_DIR, ngx.OVERRIDES = self.tmp / "redirects", self.tmp / "overrides"
        ngx.NGINX_CONF   = self.tmp / "nginx.conf"
        ngx.NGINX_LOCK   = self.tmp / "nginx.lock"
        ngx.FAILED_STATE = self.tmp / "failed-run"
        ngx.OVERRIDES_STATE = self.tmp / "overrides-loaded"
        ngx.BACKUP_BASE  = self.tmp / "backups"
        (ngx.OVERRIDES / "cms.conf").write_text("# rules v1\n")
        ngx.OVERRIDES_STATE.write_text(ngx._overrides_digest())   # nginx has loaded them
        ngx.NGINX_CONF.write_text("http { include sites-enabled/*; }\n")
        ngx._skip_logged = None
        self.calls = []
        self.test_ok, self.reload_ok = True, True
        ngx._test_nginx = lambda: (self.calls.append("test") or (self.test_ok, "emerg: bad"))
        ngx._reload_nginx = lambda logger: self.calls.append("reload") or self.reload_ok
        ngx.log_preflight_ok = lambda logger, action: True
        for k in APPLY_STEPS:
            setattr(ngx, k, lambda config, logger: False)
        self.applied = 0

    def step(self, fn):
        """Make apply_logging_features run fn (which writes through ngx._write)."""
        def apply(config, logger):
            self.applied += 1
            return bool(fn())
        ngx.apply_logging_features = apply

    def leftovers(self):
        return [p for d in (self.sites, self.ce) for p in d.iterdir() if p.name.startswith(".")]


class UndoTests(RunHarness):

    def test_failed_nginx_test_undoes_writes_creations_and_removals(self):
        (self.sites / "a.conf").write_text("orig A\n")
        (self.ce / "a.conf").write_text("ce A\n")
        (self.ce / "stale.conf").write_text("ce stale\n")

        def change():
            ngx._write(self.sites / "a.conf", "new A\n")
            ngx._write(self.ce / "new.conf", "created\n")
            ngx._unlink(self.ce / "stale.conf")
            return True
        self.step(change)
        self.test_ok = False
        ngx.run({}, LOG)
        self.assertEqual((self.sites / "a.conf").read_text(), "orig A\n")
        self.assertFalse((self.ce / "new.conf").exists())
        self.assertEqual((self.ce / "stale.conf").read_text(), "ce stale\n")
        self.assertEqual(self.calls, ["test"])
        self.assertEqual(self.leftovers(), [])

    def test_removed_cache_exclude_files_come_back_with_their_includes(self):
        # the review finding: nginx -t fails after cache-exclude was switched off;
        # the old rollback put the include lines back but not the deleted files
        ce_mod = load("nginxcacheexclude")
        ce_mod.CACHE_EXCLUDES_DIR, ce_mod.SITES_DIR = self.ce, self.sites
        ngx._cacheexclude_mod = ce_mod
        ngx._apply_cache_excludes = saved_apply = type(self).real_apply_cache_excludes
        inc = f"include {self.ce}/example.com.conf;\n"
        (self.sites / "example.com.conf").write_text("server {\n" + inc + "}\n")
        (self.ce / "example.com.conf").write_text("# rules\n")

        def strip_include():
            cf = self.sites / "example.com.conf"
            ngx._write(cf, cf.read_text().replace(inc, ""))
            return True
        self.step(strip_include)
        self.test_ok = False
        ngx.run({"nginx-cacheexclude": {"enabled": False}}, LOG)
        self.assertIn(inc, (self.sites / "example.com.conf").read_text())
        self.assertEqual((self.ce / "example.com.conf").read_text(), "# rules\n")
        self.assertIs(ngx._apply_cache_excludes, saved_apply)

    real_apply_cache_excludes = staticmethod(ngx._apply_cache_excludes)

    def test_files_changed_by_someone_else_are_left_alone(self):
        (self.sites / "a.conf").write_text("orig A\n")
        (self.sites / "b.conf").write_text("orig B\n")

        def change():
            ngx._write(self.sites / "a.conf", "ours A\n")
            ngx._write(self.sites / "b.conf", "ours B\n")
            # Enhance rewrites a.conf and deletes b.conf during the run
            (self.sites / "a.conf").write_text("enhance A\n")
            (self.sites / "b.conf").unlink()
            return True
        self.step(change)
        self.test_ok = False
        ngx.run({}, LOG)
        self.assertEqual((self.sites / "a.conf").read_text(), "enhance A\n")
        self.assertFalse((self.sites / "b.conf").exists())

    def test_exception_in_a_step_is_undone(self):
        (self.sites / "a.conf").write_text("orig A\n")

        def boom():
            ngx._write(self.sites / "a.conf", "half\n")
            raise RuntimeError("bug")
        self.step(boom)
        ngx.run({}, LOG)
        self.assertEqual((self.sites / "a.conf").read_text(), "orig A\n")
        self.assertEqual(self.calls, [])

    def test_successful_run_keeps_changes(self):
        (self.sites / "a.conf").write_text("orig A\n")
        self.step(lambda: ngx._write(self.sites / "a.conf", "new A\n") or True)
        ngx.run({}, LOG)
        self.assertEqual((self.sites / "a.conf").read_text(), "new A\n")
        self.assertEqual(self.calls, ["test", "reload"])

    def test_backup_includes_cache_excludes(self):
        (self.sites / "a.conf").write_text("A\n")
        (self.ce / "a.conf").write_text("ce\n")
        b = ngx._create_backup(LOG)
        self.assertEqual((b / "cache-excludes" / "a.conf").read_text(), "ce\n")


class FailedRunMemoryTests(RunHarness):

    def setUp(self):
        super().setUp()
        (self.sites / "a.conf").write_text("orig A\n")
        self.step(lambda: ngx._write(self.sites / "a.conf", "new A\n") or True)
        self.test_ok = False

    def test_same_inputs_not_retried(self):
        ngx.run({}, LOG)
        self.assertEqual(self.applied, 1)
        self.assertTrue(ngx.FAILED_STATE.exists())
        # the undo rewrote a.conf, inotify fires, the debounced run comes back
        for _ in range(3):
            ngx.run({}, LOG)
        self.assertEqual(self.applied, 1)
        self.assertEqual(self.calls, ["test"])

    def test_retried_when_a_vhost_changes(self):
        ngx.run({}, LOG)
        (self.sites / "a.conf").write_text("orig A, edited by Enhance\n")
        ngx.run({}, LOG)
        self.assertEqual(self.applied, 2)

    def test_retried_when_settings_change(self):
        ngx.run({}, LOG)
        ngx.run({"general": {"debounce_seconds": 5}}, LOG)
        self.assertEqual(self.applied, 2)

    def test_retried_after_retry_after(self):
        ngx.run({}, LOG)
        st = ngx._read_failed_inputs()
        st["time"] -= ngx.RETRY_AFTER + 1
        ngx.FAILED_STATE.write_text(__import__("json").dumps(st))
        ngx.run({}, LOG)
        self.assertEqual(self.applied, 2)

    def test_success_clears_the_memory(self):
        ngx.run({}, LOG)
        (self.sites / "a.conf").write_text("fixed\n")
        self.test_ok = True
        ngx.run({}, LOG)
        self.assertFalse(ngx.FAILED_STATE.exists())

    def test_reload_failure_is_remembered_across_the_restart(self):
        import logging as _logging
        exits = []
        old_exit, old_shutdown = ngx.os._exit, _logging.shutdown
        ngx.os._exit = lambda code: exits.append(code)
        _logging.shutdown = lambda: None
        self.addCleanup(setattr, ngx.os, "_exit", old_exit)
        self.addCleanup(setattr, _logging, "shutdown", old_shutdown)
        self.test_ok, self.reload_ok = True, False
        ngx.run({}, LOG)
        self.assertEqual(exits, [0])
        self.assertEqual((self.sites / "a.conf").read_text(), "orig A\n")
        ngx._skip_logged = None          # a fresh process after the restart
        ngx.run({}, LOG)
        self.assertEqual(self.applied, 1)


class OverrideReloadTests(RunHarness):

    def test_changed_override_is_tested_and_reloaded_once(self):
        ngx.run({}, LOG)
        self.assertEqual(self.calls, [])
        (ngx.OVERRIDES / "cms.conf").write_text("# rules v2\n")    # git pull
        ngx.run({}, LOG)
        self.assertEqual(self.calls, ["test", "reload"])
        ngx.run({}, LOG)
        self.assertEqual(self.calls, ["test", "reload"])

    def test_unknown_state_reloads_once(self):
        ngx.OVERRIDES_STATE.unlink()
        ngx.run({}, LOG)
        ngx.run({}, LOG)
        self.assertEqual(self.calls, ["test", "reload"])

    def test_broken_override_is_not_retried_in_a_loop(self):
        (ngx.OVERRIDES / "cms.conf").write_text("# broken\n")
        self.test_ok = False
        for _ in range(3):
            ngx.run({}, LOG)
        self.assertEqual(self.calls, ["test"])
        self.assertNotEqual(ngx._read_text(ngx.OVERRIDES_STATE), ngx._overrides_digest())


class LockTests(RunHarness):

    def test_runs_do_not_overlap(self):
        active, peak = [0], [0]
        guard = threading.Lock()

        def slow():
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.2)
            with guard:
                active[0] -= 1
            return False
        self.step(slow)
        threads = [threading.Thread(target=ngx.run, args=({}, LOG)) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.applied, 3)
        self.assertEqual(peak[0], 1)

    def test_lock_excludes_other_module_instances(self):
        # nginxtune and nginxredirects each load their own copy of nginxconf
        other = load("nginxconf")
        path = self.tmp / "shared.lock"
        order = []
        held = threading.Event()

        def holder():
            with nc.nginx_lock(path):
                held.set()
                time.sleep(0.3)
                order.append("holder done")

        t = threading.Thread(target=holder)
        t.start()
        held.wait()
        with other.nginx_lock(path):
            order.append("waiter in")
        t.join()
        self.assertEqual(order, ["holder done", "waiter in"])

    def test_redirects_and_nginxtune_share_the_lock_file(self):
        nrd = load("nginxredirects")
        self.assertEqual(nrd.NGINX_LOCK, load("nginxtune").NGINX_LOCK)

    def test_cleanup_takes_the_lock(self):
        seen = []
        orig = ngx._cleanup_locked
        self.addCleanup(setattr, ngx, "_cleanup_locked", orig)

        def probe(logger):
            import fcntl
            fd = os.open(ngx.NGINX_LOCK, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen.append("free")
            except BlockingIOError:
                seen.append("held")
            finally:
                os.close(fd)
        ngx._cleanup_locked = probe
        ngx.cleanup(LOG)
        self.assertEqual(seen, ["held"])


class WriteAtomicTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_keeps_mode_and_leaves_no_temp_files(self):
        f = self.tmp / "a.conf"
        f.write_text("old")
        os.chmod(f, 0o600)
        nc.write_atomic(f, "new")
        self.assertEqual(f.read_text(), "new")
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["a.conf"])

    def test_new_file_is_0644(self):
        f = self.tmp / "n.conf"
        nc.write_atomic(f, b"x")
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o644)

    def test_symlink_kept_and_target_written(self):
        target = self.tmp / "available.conf"
        target.write_text("old")
        link = self.tmp / "enabled.conf"
        link.symlink_to(target)
        nc.write_atomic(link, "new")
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(), "new")

    def test_failure_leaves_the_original(self):
        f = self.tmp / "a.conf"
        f.write_text("old")
        real = os.replace

        def broken(a, b):
            raise OSError("disk full")
        os.replace = broken
        try:
            with self.assertRaises(OSError):
                nc.write_atomic(f, "new")
        finally:
            os.replace = real
        self.assertEqual(f.read_text(), "old")
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["a.conf"])

    def test_temp_name_is_invisible_to_include_globs_and_watchers(self):
        names = []
        real = os.replace

        def spy(a, b):
            names.append(os.path.basename(a))
            return real(a, b)
        os.replace = spy
        try:
            nc.write_atomic(self.tmp / "a.conf", "x")
        finally:
            os.replace = real
        self.assertTrue(names[0].startswith("."))
        self.assertFalse(names[0].endswith(".conf"))


def _if_regexes(name):
    """The `if ($uri ~* "...")` patterns of an override file."""
    text = (REPO / "overrides" / name).read_text()
    pats = re.findall(r'^if \(\$uri ~\* "((?:[^"\\]|\\.)*)"\) \{ return 403; \}$', text, re.M)
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert len(pats) == len(lines), (name, lines)
    return [re.compile(p, re.I) for p in pats]


def _blocked(name, uri):
    return any(r.search(uri) for r in _if_regexes(name))


class OverrideRuleTests(unittest.TestCase):
    """Python's re agrees with PCRE on these patterns (classes, alternation,
    one negative lookahead). Behaviour in a real nginx is checked separately."""

    CMS_BLOCKED = [
        "/wp-config.php", "/blog/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/wp-config.php~", "/.wp-config.php.swp", "/wp-config.bak", "/wp-config.txt",
        "/wp-config-sample.php", "/WP-CONFIG.PHP.BAK",
        "/readme.html", "/blog/readme.html", "/wp-content/plugins/x/readme.txt", "/license.txt",
        "/backup.sql", "/db/dump.sql.gz", "/index.php.bak", "/style.css.orig", "/x.old",
        "/backup.zip", "/public_html.tar.gz", "/site.tgz", "/x.wpress", "/wp-content/backup.zip",
        "/wp-content/debug.log", "/blog/wp-content/debug.log",
        "/wp-content/uploads/wc-logs/fatal-errors-2026-11-27-abc.log", "/error_log",
        "/wp-admin/error_log", "/php_errorlog",
        "/wp-content/uploads/shell.php", "/blog/wp-content/uploads/2026/11/x.php",
        "/wp-content/cache/x.PHP", "/wp-content/ai1wm-backups/x.php",
        "/wp-includes/class-wp.php", "/blog/wp-includes/version.php",
    ]
    CMS_ALLOWED = [
        "/", "/index.php", "/wp-login.php", "/wp-admin/admin-ajax.php", "/wp-cron.php",
        "/blog/index.php", "/wp-content/themes/t/style.css", "/wp-content/uploads/2026/11/a.jpg",
        "/wp-content/uploads/2026/11/catalog.zip", "/downloads/brochure.zip",
        "/wp-content/plugins/woocommerce/assets/js/x.js", "/wp-content/plugins/p/ajax.php",
        "/wp-includes/js/tinymce/wp-tinymce.php", "/wp-includes/ms-files.php",
        "/wp-includes/js/jquery/jquery.min.js", "/sitemap.xml", "/sitemap.xml.gz",
        "/robots.txt", "/my-account/orders/", "/wp-json/wp/v2/posts", "/xmlrpc.php",
        "/wp-content/uploads/report.log.jpg", "/config.php", "/wp-configurator/",
        "/.well-known/acme-challenge/abc",
    ]

    def test_cms_blocks(self):
        for uri in self.CMS_BLOCKED:
            self.assertTrue(_blocked("cms.conf", uri), uri)

    def test_cms_allows(self):
        for uri in self.CMS_ALLOWED:
            self.assertFalse(_blocked("cms.conf", uri), uri)

    def test_xmlrpc(self):
        for uri in ("/xmlrpc.php", "/blog/xmlrpc.php", "/XMLRPC.PHP", "/a/b/xmlrpc.php"):
            self.assertTrue(_blocked("xmlrpc.conf", uri), uri)
        for uri in ("/", "/xmlrpc.php.html", "/wp-login.php", "/my-xmlrpc.php/x"):
            self.assertFalse(_blocked("xmlrpc.conf", uri), uri)

    def test_overrides_parse(self):
        for name in ("cms.conf", "xmlrpc.conf"):
            ds = nc.parse((REPO / "overrides" / name).read_text())
            self.assertTrue(ds and all(d.name in ("if", "return") for d in ds), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
