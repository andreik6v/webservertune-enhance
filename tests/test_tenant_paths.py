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
        res = fcc.deploy_mu_plugin(UUID, b"<?php // plugin\n")
        self.assertTrue(all(ok for _, ok, _ in res), res)
        for p in ("public_html", "public_html/blog"):
            f = self.ws / p / "wp-content/mu-plugins/fastcgiclear.php"
            self.assertEqual(f.read_bytes(), b"<?php // plugin\n")
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
        # idempotent
        res = fcc.deploy_mu_plugin(UUID, b"<?php // plugin\n")
        self.assertTrue(all(ok for _, ok, _ in res), res)

    def test_mu_plugins_dir_symlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").symlink_to(self.v.dir)
        res = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(len(res), 1)
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)

    def test_mu_plugin_file_symlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").mkdir()
        (root / "wp-content/mu-plugins/fastcgiclear.php").symlink_to(self.v.file)
        res = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)

    def test_wp_content_symlink_refused(self):
        root = self.ws / "public_html"
        root.mkdir()
        (root / "wp-config.php").write_text("<?php\n")
        (root / "wp-content").symlink_to(self.v.dir)
        res = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertTrue(all(not ok for _, ok, _ in res))
        self.v.assert_untouched(self)

    def test_symlinked_directory_not_walked(self):
        # a symlinked dir that looks like a WordPress root must not be found
        fake = self.v.root / "fakewp"
        (fake / "wp-content").mkdir(parents=True)
        (fake / "wp-config.php").write_text("<?php\n")
        os.chmod(fake / "wp-content", 0o700)
        (self.ws / "public_html").symlink_to(fake)
        res = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(res, [])
        self.assertFalse((fake / "wp-content/mu-plugins").exists())

    def test_mu_plugin_hardlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").mkdir()
        os.link(self.v.file, root / "wp-content/mu-plugins/fastcgiclear.php")
        res = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)


class NginxtuneLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
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

    def test_site_log_dir_bad_uuid_refused(self):
        for name in ("../../etc", "abc", "", UUID + "/x"):
            self.assertFalse(ngx._ensure_site_log_dir(name, LOG))
        self.assertFalse((self.tmp / "etc").exists())

    def test_filewatcher_refuses_symlink_and_fifo(self):
        ws = self.tmp / "ws"
        ws.mkdir()
        (ws / "php-error.log").symlink_to(self.v.file)
        fw = ngx.FileWatcher(str(ws / "php-error.log"), LOG, seek_to_end_on_open=False)
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
        ngx.SITES_DIR = self.tmp / "sites-enabled"
        ngx.SITES_DIR.mkdir()
        ngx.SITE_LOGS_DIR = self.tmp / "logs"
        self.conf = ngx.SITES_DIR / "example.com.conf"
        self.conf.write_text(VHOST)

    def cfg(self, pers, conn=False):
        return {"general": {"persistent_logging": pers},
                "nginx": {"features": {"connection_ip_logging": conn}}}

    def test_legacy_line_migrated_when_enabled(self):
        self.assertTrue(ngx.apply_logging_features(self.cfg(True), LOG))
        text = self.conf.read_text()
        self.assertNotIn("access_log /var/www/", text)
        self.assertIn(f"access_log {ngx.SITE_LOGS_DIR}/{UUID}/webserver.log example.com_persistent;", text)
        self.assertEqual(text.count("_persistent;"), 1)
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

    def test_no_webspace_writes(self):
        # nothing under a fake /var/www may be created by the logging code
        ngx.apply_logging_features(self.cfg(True), LOG)
        self.assertFalse(Path(f"/var/www/{UUID}").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
