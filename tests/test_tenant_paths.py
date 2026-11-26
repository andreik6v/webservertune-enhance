#!/usr/bin/env python3
"""
Regression tests: root must never follow tenant-controlled symlinks.

The service runs as root while /var/www/<uuid> belongs to the website user.
These tests build a fake /var/www in a temporary directory, plant symlinks,
FIFOs and hard links the way a hostile tenant would, and check that files
outside the webspace ("victims") are never written, chowned or chmodded.

They run unprivileged (chown to your own uid is allowed), so the attack shows
up as a changed mode or content on the victim. Run with:

    python3 -m unittest discover -s tests -v
"""

import importlib.machinery
import importlib.util
import logging
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UUID = "11111111-2222-3333-4444-555555555555"
# When the suite runs as root (like the service), the fake webspace is given to an
# unprivileged "tenant" uid, so ownership changes on victims are detected too.
AS_ROOT = os.geteuid() == 0
TENANT  = 65534 if AS_ROOT else os.geteuid()


def give_to_tenant(path):
    if AS_ROOT:
        for dirpath, dirnames, filenames in os.walk(path):
            os.lchown(dirpath, TENANT, TENANT)
            for n in dirnames + filenames:
                os.lchown(os.path.join(dirpath, n), TENANT, TENANT)


def load(name):
    loader = importlib.machinery.SourceFileLoader(name, str(REPO / "modules" / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


fcc = load("fastcgiclear")
ngx = load("nginxtune")
LOG = logging.getLogger("test")
LOG.addHandler(logging.NullHandler())


class Victims:
    """Files and dirs outside the fake webspace that must stay untouched."""

    def __init__(self, root):
        self.root = root / "outside"
        self.root.mkdir()
        self.file = self.root / "victim.txt"
        self.file.write_text("secret\n")
        os.chmod(self.file, 0o600)
        self.dir = self.root / "victimdir"
        self.dir.mkdir()
        os.chmod(self.dir, 0o700)
        self.uids = (os.lstat(self.file).st_uid, os.lstat(self.dir).st_uid)

    def assert_untouched(self, tc):
        tc.assertEqual(self.file.read_text(), "secret\n")
        tc.assertEqual(stat.S_IMODE(os.lstat(self.file).st_mode), 0o600)
        tc.assertEqual(stat.S_IMODE(os.lstat(self.dir).st_mode), 0o700)
        tc.assertEqual(os.listdir(self.dir), [])
        tc.assertEqual((os.lstat(self.file).st_uid, os.lstat(self.dir).st_uid), self.uids)


class FastcgiclearTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.www = self.tmp / "www"
        self.www.mkdir()
        # like production: /var/www is 0711, so the site user can reach its webspace
        os.chmod(self.tmp, 0o711)
        os.chmod(self.www, 0o711)
        fcc.WWW_DIR = self.www
        self.ws = self.www / UUID
        self.ws.mkdir()
        give_to_tenant(self.ws)
        self.v = Victims(self.tmp)

    def wp(self, *sub):
        root = self.ws.joinpath(*sub)
        (root / "wp-content").mkdir(parents=True)
        (root / "wp-config.php").write_text("<?php\n")
        give_to_tenant(self.ws)
        return root

    # --- clear.cache -------------------------------------------------------

    def test_flag_created_normally(self):
        fcc.ensure_flag_file(UUID)
        f = self.ws / "clear.cache"
        self.assertTrue(f.is_file() and not f.is_symlink())
        self.assertEqual(f.read_text(), "cache=cleared\n")
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
        self.assertEqual(fcc.read_flag(UUID), "cache=cleared")

    def test_flag_symlink_refused_by_ensure(self):
        (self.ws / "clear.cache").symlink_to(self.v.file)
        with self.assertRaises(fcc.UnsafePath):
            fcc.ensure_flag_file(UUID)
        self.v.assert_untouched(self)

    def test_flag_symlink_refused_by_reset(self):
        (self.ws / "clear.cache").symlink_to(self.v.file)
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        self.v.assert_untouched(self)

    def test_flag_symlink_not_read(self):
        (self.ws / "clear.cache").symlink_to(self.v.file)
        with self.assertRaises(fcc.UnsafePath):
            fcc.read_flag(UUID)

    def test_flag_dangling_symlink_not_created(self):
        target = self.v.root / "created-by-root"
        (self.ws / "clear.cache").symlink_to(target)
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        self.assertFalse(target.exists())

    def test_flag_fifo_does_not_block(self):
        os.mkfifo(self.ws / "clear.cache")
        done = {}

        def run():
            try:
                fcc.read_flag(UUID)
            except fcc.UnsafePath:
                done["refused"] = True
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(3)
        self.assertFalse(t.is_alive(), "read_flag blocked on a FIFO")
        self.assertTrue(done.get("refused"))

    def test_flag_hardlink_refused(self):
        os.link(self.v.file, self.ws / "clear.cache")
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        self.v.assert_untouched(self)

    def test_webspace_itself_symlink_refused(self):
        other = "99999999-2222-3333-4444-555555555555"
        (self.www / other).symlink_to(self.v.dir)
        with self.assertRaises(fcc.UnsafePath):
            fcc.ensure_flag_file(other)
        self.v.assert_untouched(self)

    def test_bad_uuid_refused(self):
        for name in ("../etc", "", "x/y", UUID + "/.."):
            with self.assertRaises(fcc.UnsafePath):
                fcc.open_webspace(name)

    # --- mu-plugin deployment ----------------------------------------------

    def test_mu_plugin_deployed_root_and_subdir(self):
        self.wp("public_html")
        self.wp("public_html", "blog")
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php // plugin\n")
        self.assertIsNone(note)
        self.assertEqual(len(res), 2)
        self.assertTrue(all(ok for _, ok, _ in res), res)
        for p in ("public_html", "public_html/blog"):
            f = self.ws / p / "wp-content/mu-plugins/fastcgiclear.php"
            self.assertEqual(f.read_bytes(), b"<?php // plugin\n")
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
            self.assertEqual(f.stat().st_uid, TENANT)
            self.assertEqual(f.parent.stat().st_uid, TENANT)
        # idempotent
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php // plugin\n")
        self.assertTrue(all(ok for _, ok, _ in res), res)

    def test_mu_plugins_dir_symlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").symlink_to(self.v.dir)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(len(res), 1)
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)

    def test_mu_plugin_file_symlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").mkdir()
        (root / "wp-content/mu-plugins/fastcgiclear.php").symlink_to(self.v.file)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)

    def test_wp_content_symlink_refused(self):
        root = self.ws / "public_html"
        root.mkdir()
        (root / "wp-config.php").write_text("<?php\n")
        (root / "wp-content").symlink_to(self.v.dir)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertTrue(all(not ok for _, ok, _ in res))
        self.v.assert_untouched(self)

    def test_symlinked_directory_not_walked(self):
        # a symlinked dir that looks like a WordPress root must not be found
        fake = self.v.root / "fakewp"
        (fake / "wp-content").mkdir(parents=True)
        (fake / "wp-config.php").write_text("<?php\n")
        os.chmod(fake / "wp-content", 0o700)
        (self.ws / "public_html").symlink_to(fake)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(res, [])
        self.assertFalse((fake / "wp-content/mu-plugins").exists())

    def test_mu_plugin_hardlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").mkdir()
        os.link(self.v.file, root / "wp-content/mu-plugins/fastcgiclear.php")
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)


    # --- ownership: never hand over something we did not create ------------

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_flag_root_owned_refused(self):
        f = self.ws / "clear.cache"
        f.write_text("x\n")
        os.chmod(f, 0o600)
        with self.assertRaises(fcc.UnsafePath):
            fcc.ensure_flag_file(UUID)
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        st = os.lstat(f)
        self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode), f.read_text()), (0, 0o600, "x\n"))

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_flag_created_owned_by_tenant(self):
        fcc.ensure_flag_file(UUID)
        self.assertEqual(os.lstat(self.ws / "clear.cache").st_uid, TENANT)

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_mu_dir_root_owned_refused(self):
        root = self.wp("public_html")
        mu = root / "wp-content/mu-plugins"
        mu.mkdir()
        os.chmod(mu, 0o700)       # root-owned, e.g. a directory the tenant moved into place
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        st = os.lstat(mu)
        self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (0, 0o700))
        self.assertEqual(os.listdir(mu), [])

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_mu_file_root_owned_refused(self):
        root = self.wp("public_html")
        mu = root / "wp-content/mu-plugins"
        mu.mkdir()
        os.lchown(mu, TENANT, TENANT)
        f = mu / "fastcgiclear.php"
        f.write_text("root\n")
        os.chmod(f, 0o600)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.assertEqual((os.lstat(f).st_uid, f.read_text()), (0, "root\n"))

    # --- bounded search ----------------------------------------------------

    def _with(self, **kw):
        old = {k: getattr(fcc, k) for k in kw}
        for k, v in kw.items():
            setattr(fcc, k, v)
        self.addCleanup(lambda: [setattr(fcc, k, v) for k, v in old.items()])

    def test_walk_depth_limit(self):
        self.wp("a", "b", "c")
        self._with(WALK_MAX_DEPTH=2)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(res, [])
        self._with(WALK_MAX_DEPTH=3)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual([r[0] for r in res], ["a/b/c/wp-content/mu-plugins/fastcgiclear.php"])

    def test_walk_roots_and_dirs_limits(self):
        self.wp("s1")
        self.wp("s2")
        self._with(WALK_MAX_ROOTS=1)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(len(res), 1)
        self.assertIn("roots", note)
        self._with(WALK_MAX_ROOTS=50, WALK_MAX_DIRS=2)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertIn("directories", note)

    def test_walk_skips_wp_content_and_files_named_like_dirs(self):
        root = self.wp("public_html")
        # a nested "WordPress" inside wp-content must not be treated as a root
        (root / "wp-content/plugins/x/wp-content").mkdir(parents=True)
        (root / "wp-content/plugins/x/wp-config.php").write_text("")
        # wp-content as a regular file is not a root either
        (self.ws / "other").mkdir()
        (self.ws / "other/wp-config.php").write_text("")
        (self.ws / "other/wp-content").write_text("")
        give_to_tenant(self.ws)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual([r[0] for r in res], ["public_html/wp-content/mu-plugins/fastcgiclear.php"])

    # --- cache directories -------------------------------------------------

    def test_cache_dir_trust(self):
        croot = self.tmp / "nginx_cache"
        croot.mkdir()
        os.chmod(croot, 0o755)
        self._with(TRUSTED_CACHE_ROOT=croot)
        (croot / "example.com").mkdir()
        (croot / "link.com").symlink_to(self.v.dir)
        (croot / "deep").mkdir()
        (croot / "deep" / "x").mkdir()
        self.assertTrue(fcc.cache_dir_is_trusted(croot / "example.com"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "link.com"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "deep" / "x"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "missing"))
        self.assertFalse(fcc.cache_dir_is_trusted(self.v.dir))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / ".." / "outside"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot))
        os.chmod(croot, 0o777)
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "example.com"))
        os.chmod(croot, 0o755)


    def test_walk_entry_limit(self):
        for i in range(5):
            (self.ws / f"d{i}").mkdir()
        give_to_tenant(self.ws)
        self._with(WALK_MAX_ENTRIES=3)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertIn("entries", note)

    def test_mkdir_as_other_user_refused_unprivileged(self):
        if AS_ROOT:
            self.skipTest("unprivileged only")
        with self.assertRaises(fcc.UnsafePath):
            fcc._mkdir_as(self.ws / "x", os.geteuid() + 1, os.getegid())
        self.assertFalse((self.ws / "x").exists())

    def test_find_cache_paths_matches_enhance_log_only(self):
        sites = self.tmp / "sites-enabled"
        sites.mkdir()
        self._with(SITES_DIR=sites)
        other = "99999999-2222-3333-4444-555555555555"
        (sites / "a.conf").write_text(
            "fastcgi_cache_path /c/a levels=1:2 keys_zone=a:10m;\n"
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log a;\n")
        (sites / "a-preview.conf").write_text(
            "fastcgi_cache_path /c/ap levels=1:2 keys_zone=ap:10m;\n"
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log ap;\n")
        (sites / "b.conf").write_text(
            f"# moved from {UUID}\nroot /var/www/{UUID}/x;\n"
            "fastcgi_cache_path /c/b levels=1:2 keys_zone=b:10m;\n"
            f"access_log /var/local/enhance/webserver_logs/{other}.log b;\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/ap"])

    def test_clear_cache_dir_empties_without_following_links(self):
        c = self.tmp / "cache"
        (c / "1" / "ab").mkdir(parents=True)
        (c / "1" / "ab" / "key").write_text("x")
        (c / "f").write_text("x")
        (c / "link").symlink_to(self.v.dir)
        (c / "1" / "dlink").symlink_to(self.v.dir)
        self.assertEqual(fcc.clear_cache_dir(c), [])
        self.assertEqual(os.listdir(c), [])
        self.v.assert_untouched(self)

    def test_clear_cache_dir_vanished_entries_are_not_errors(self):
        # nginx's cache manager can expire entries while we delete; simulate the
        # error rmtree reports then, and a real failure for comparison
        c = self.tmp / "cache"
        (c / "1" / "ab").mkdir(parents=True)
        real = fcc.shutil.rmtree

        def fake(exc_type):
            def rmtree(path, onexc=None, onerror=None):
                real(path)
                exc = exc_type(2, "simulated", path)
                if onexc:
                    onexc(os.unlink, path, exc)
                else:
                    onerror(os.unlink, path, (exc_type, exc, None))
            return rmtree
        try:
            fcc.shutil.rmtree = fake(FileNotFoundError)
            self.assertEqual(fcc.clear_cache_dir(c), [])
            (c / "2").mkdir()
            fcc.shutil.rmtree = fake(PermissionError)
            self.assertEqual(len(fcc.clear_cache_dir(c)), 1)
        finally:
            fcc.shutil.rmtree = real

    def test_clear_cache_dir_reports_failures(self):
        if AS_ROOT:
            self.skipTest("root ignores permissions")
        c = self.tmp / "cache"
        (c / "locked").mkdir(parents=True)
        (c / "locked" / "f").write_text("x")
        os.chmod(c / "locked", 0o500)
        try:
            self.assertTrue(fcc.clear_cache_dir(c))
        finally:
            os.chmod(c / "locked", 0o700)


def ngx_env(tmp):
    """Point nginxtune at a temp tree; the worker user is nobody (exists everywhere)."""
    (tmp / "nginx.conf").write_text("user nobody;\nworker_processes auto;\n")
    ngx.NGINX_CONF = tmp / "nginx.conf"
    ngx._acl_done.clear()


class NginxtuneLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ngx_env(self.tmp)
        ngx.SITE_LOGS_DIR = self.tmp / "sites"
        self.v = Victims(self.tmp)

    def test_site_log_dir_created(self):
        self.assertTrue(ngx._ensure_site_log_dir(UUID, LOG))
        d = ngx.SITE_LOGS_DIR / UUID
        self.assertTrue(d.is_dir() and not d.is_symlink())

    def test_site_log_dir_symlink_refused(self):
        ngx.SITE_LOGS_DIR.mkdir()
        (ngx.SITE_LOGS_DIR / UUID).symlink_to(self.v.dir)
        self.assertFalse(ngx._ensure_site_log_dir(UUID, LOG))
        self.v.assert_untouched(self)

    @unittest.skipUnless(AS_ROOT, "ownership and ACLs need root")
    def test_site_log_dir_owner_mode_acl(self):
        self.assertTrue(ngx._ensure_site_log_dir(UUID, LOG))
        import subprocess
        for d in (ngx.SITE_LOGS_DIR, ngx.SITE_LOGS_DIR / UUID):
            st = os.lstat(d)
            self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (0, 0o750))
            acl = subprocess.run(["getfacl", "-cp", str(d)], capture_output=True, text=True).stdout
            self.assertIn("user:nobody:--x", acl)

    def test_site_log_dir_unsafe_parent_refused(self):
        os.chmod(self.tmp, 0o777)
        try:
            self.assertFalse(ngx._ensure_site_log_dir(UUID, LOG))
            self.assertFalse(ngx.SITE_LOGS_DIR.exists())
        finally:
            os.chmod(self.tmp, 0o700)

    def test_site_log_dir_foreign_owner_refused(self):
        if not AS_ROOT:
            self.skipTest("needs root")
        ngx.SITE_LOGS_DIR.mkdir()
        os.chown(ngx.SITE_LOGS_DIR, TENANT, TENANT)
        self.assertFalse(ngx._ensure_site_log_dir(UUID, LOG))
        self.assertEqual(os.lstat(ngx.SITE_LOGS_DIR).st_uid, TENANT)

    def test_site_log_dir_bad_uuid_refused(self):
        for name in ("../../etc", "abc", "", UUID + "/x", UUID + "\n"):
            self.assertFalse(ngx._ensure_site_log_dir(name, LOG))
        self.assertFalse((self.tmp / "etc").exists())

    def test_filewatcher_refuses_symlink_and_fifo(self):
        ws = self.tmp / "ws"
        ws.mkdir()
        (ws / "php-error.log").symlink_to(self.v.file)
        fw = ngx.FileWatcher(str(ws / "php-error.log"), LOG, seek_to_end_on_open=False)
        self.assertIsNone(fw.fh, "opened a symlink")
        self.assertEqual(fw.readlines(), [])
        fw.close()
        os.unlink(ws / "php-error.log")
        os.mkfifo(ws / "php-error.log")
        out = {}
        t = threading.Thread(target=lambda: out.setdefault(
            "lines", ngx.FileWatcher(str(ws / "php-error.log"), LOG, False).readlines()), daemon=True)
        t.start()
        t.join(3)
        self.assertFalse(t.is_alive(), "FileWatcher blocked on a FIFO")
        self.assertEqual(out.get("lines"), [])

    def test_filewatcher_refuses_hardlink(self):
        ws = self.tmp / "ws"
        ws.mkdir()
        os.link(self.v.file, ws / "php-error.log")
        fw = ngx.FileWatcher(str(ws / "php-error.log"), LOG, seek_to_end_on_open=False)
        self.assertIsNone(fw.fh, "opened a hard link")
        self.assertEqual(fw.readlines(), [])
        fw.close()

    def test_filewatcher_reads_regular_file(self):
        f = self.tmp / "real.log"
        f.write_text("a\nb\n")
        fw = ngx.FileWatcher(str(f), LOG, seek_to_end_on_open=False)
        self.assertEqual(fw.readlines(), ["a\n", "b\n"])
        fw.close()


VHOST = """log_format example.com "\\"$remote_addr\\" \\"$msec\\"";
log_format example.com_persistent '$time_local - $remote_addr - $http_cf_ipcountry - $server_protocol - $status - $request_method - $host - $request_uri - $http_user_agent - $upstream_cache_status - $request_time - $upstream_response_time';
server {
listen 80;
server_name example.com;
access_log /var/local/enhance/webserver_logs/%(uuid)s.log example.com;
access_log /var/www/%(uuid)s/logs/webserver.log example.com_persistent;
root "/var/www/%(uuid)s/public_html";
location ~ \\.php$ {
    fastcgi_pass 127.0.0.1:9000;
}
include vhost_includes/example.com.conf;
}
""" % {"uuid": UUID}


class NginxtuneMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ngx_env(self.tmp)
        ngx.SITES_DIR = self.tmp / "sites-enabled"
        ngx.SITES_DIR.mkdir()
        ngx.SITE_LOGS_DIR = self.tmp / "logs"
        self.conf = ngx.SITES_DIR / "example.com.conf"
        self.conf.write_text(VHOST)

    def settle(self, cfg):
        """Apply until stable; must converge on the second pass with no change."""
        ngx.apply_logging_features(cfg, LOG)
        before = self.conf.read_text()
        self.assertFalse(ngx.apply_logging_features(cfg, LOG), "second pass changed the file")
        self.assertEqual(self.conf.read_text(), before)
        return before

    def assert_consistent(self, text):
        fmt = text.count("_persistent '")
        log = text.count("_persistent;")
        self.assertEqual(fmt, log, "persistent format and access_log out of step")
        self.assertLessEqual(fmt, 1)

    def cfg(self, pers, conn=False):
        return {"general": {"persistent_logging": pers},
                "nginx": {"features": {"connection_ip_logging": conn}}}

    def test_legacy_line_migrated_when_enabled(self):
        self.assertTrue(ngx.apply_logging_features(self.cfg(True), LOG))
        text = self.conf.read_text()
        self.assertNotIn("access_log /var/www/", text)
        self.assertIn(f"access_log {ngx.SITE_LOGS_DIR}/{UUID}/webserver.log example.com_persistent;", text)
        self.assertEqual(text.count("_persistent;"), 1)
        # the legacy line is removed as a whole line, not left behind as blank space
        self.assertEqual([l for l in text.splitlines() if not l.strip()], [])
        self.assertTrue((ngx.SITE_LOGS_DIR / UUID).is_dir())
        # idempotent
        self.assertFalse(ngx.apply_logging_features(self.cfg(True), LOG))

    def test_legacy_line_removed_when_disabled(self):
        self.assertTrue(ngx.apply_logging_features(self.cfg(False), LOG))
        text = self.conf.read_text()
        self.assertNotIn("access_log /var/www/", text)
        self.assertNotIn("/webserver.log", text)
        self.assertFalse(ngx.apply_logging_features(self.cfg(False), LOG))

    def test_connection_ip_still_applied_after_migration(self):
        ngx.apply_logging_features(self.cfg(True, conn=True), LOG)
        text = self.conf.read_text()
        self.assertIn("$realip_remote_addr - $http_cf_ray';", text)
        self.assertFalse(ngx.apply_logging_features(self.cfg(True, conn=True), LOG))
        # turning everything off removes the persistent log entirely
        self.assertTrue(ngx.apply_logging_features(self.cfg(False), LOG))
        self.assertNotIn("/webserver.log", self.conf.read_text())

    def test_odd_legacy_forms_stripped(self):
        odd = VHOST.replace(
            f"access_log /var/www/{UUID}/logs/webserver.log example.com_persistent;",
            f'access_log\t"/var/www/{UUID}/logs/webserver.log"\n        example.com_persistent;\n'
            f"  access_log '/var/www/{UUID}/other.log' example.com;\n"
            f"location /x {{ access_log /var/www/{UUID}/x.log; return 204; }}")
        self.conf.write_text(odd)
        for pers in (True, False):
            text = self.settle(self.cfg(pers))
            self.assertNotRegex(text, r"access_log\s+[\"']?/var/www")
            self.assertIn("location /x {  return 204; }", text)
            self.assert_consistent(text)

    def test_vhost_without_uuid_converges_without_orphans(self):
        no_uuid = VHOST.replace(
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log example.com;\n", "")
        self.conf.write_text(no_uuid)
        text = self.settle(self.cfg(True))
        self.assertNotIn("_persistent", text)
        self.assertNotIn("/var/www/" + UUID + "/logs", text)

    def test_orphan_format_removed(self):
        orphan = VHOST.replace(
            f"access_log /var/www/{UUID}/logs/webserver.log example.com_persistent;\n", "")
        self.conf.write_text(orphan)
        text = self.settle(self.cfg(False))
        self.assertNotIn("_persistent", text)

    def test_log_dir_failure_means_no_persistent_lines(self):
        ngx.SITE_LOGS_DIR.mkdir()
        (ngx.SITE_LOGS_DIR / UUID).symlink_to(self.tmp)
        text = self.settle(self.cfg(True))
        self.assertNotIn("_persistent", text)
        self.assertNotIn("/var/www/" + UUID + "/logs", text)

    def test_dotted_format_name_used_for_both_lines(self):
        text = self.settle(self.cfg(True))
        self.assertIn("log_format example.com_persistent '", text)
        self.assertIn("webserver.log example.com_persistent;", text)
        self.assert_consistent(text)

    def test_unchanged_file_not_rewritten(self):
        self.settle(self.cfg(True))
        m1 = os.stat(self.conf).st_mtime_ns
        self.assertFalse(ngx.apply_logging_features(self.cfg(True), LOG))
        self.assertEqual(os.stat(self.conf).st_mtime_ns, m1)

    def test_multiline_log_format_gets_no_persistent_lines(self):
        ml = VHOST.replace('log_format example.com "\\"$remote_addr\\" \\"$msec\\"";',
                           'log_format example.com "\\"$remote_addr\\""\n    "\\"$msec\\"";')
        self.assertIn('\n    "', ml)
        self.conf.write_text(ml)
        text = self.settle(self.cfg(True))
        self.assertNotIn("_persistent", text)
        self.assertIn('\n    "', text)

    def test_every_enhance_log_gets_its_persistent_line(self):
        two = VHOST.replace("include vhost_includes/example.com.conf;\n}\n",
            "include vhost_includes/example.com.conf;\n}\nserver {\nlisten 443;\n"
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log example.com;\n}}\n")
        self.conf.write_text(two)
        text = self.settle(self.cfg(True))
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 2)
        self.assertEqual(text.count("log_format example.com_persistent"), 1)

    def test_wrong_destination_is_corrected(self):
        other = "99999999-2222-3333-4444-555555555555"
        self.settle(self.cfg(True))
        self.conf.write_text(self.conf.read_text().replace(f"{UUID}/webserver.log", f"{other}/webserver.log"))
        text = self.settle(self.cfg(True))
        self.assertNotIn(other, text)
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)

    def test_duplicate_persistent_format_reduced(self):
        text = self.settle(self.cfg(True))
        fmt = [l for l in text.splitlines(keepends=True) if "log_format example.com_persistent" in l][0]
        self.conf.write_text(text.replace(fmt, fmt + fmt))
        text = self.settle(self.cfg(True))
        self.assertEqual(text.count("log_format example.com_persistent"), 1)

    def test_no_webspace_writes(self):
        # nothing under a fake /var/www may be created by the logging code
        ngx.apply_logging_features(self.cfg(True), LOG)
        self.assertFalse(Path(f"/var/www/{UUID}").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
