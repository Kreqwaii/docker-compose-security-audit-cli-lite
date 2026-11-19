import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from compose_audit import (
    SimpleYAMLParser,
    audit_compose,
    format_json,
    format_markdown,
    format_text,
    main,
    should_fail,
)


SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_compose"


class TestSimpleYAMLParser(unittest.TestCase):
    def setUp(self):
        self.parser = SimpleYAMLParser()

    def test_empty_input(self):
        self.assertEqual(self.parser.parse(""), {})

    def test_comments_only(self):
        self.assertEqual(self.parser.parse("# comment\n   # another"), {})

    def test_basic_mapping_and_scalars(self):
        yml = "version: '3.9'\nenabled: true\ncount: 3\nratio: 1.5\n"
        res = self.parser.parse(yml)
        self.assertEqual(res["version"], "3.9")
        self.assertIs(res["enabled"], True)
        self.assertEqual(res["count"], 3)
        self.assertEqual(res["ratio"], 1.5)

    def test_nested_services_and_lists(self):
        yml = (
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
            "    ports:\n"
            "      - '80:80'\n"
            "      - '443:443'\n"
        )
        res = self.parser.parse(yml)
        self.assertEqual(res["services"]["web"]["image"], "nginx:1.25")
        self.assertEqual(res["services"]["web"]["ports"], ["80:80", "443:443"])

    def test_inline_list_and_dict(self):
        yml = 'cmd: ["echo", "hello"]\nlabels: {env: prod, tier: api}\n'
        res = self.parser.parse(yml)
        self.assertEqual(res["cmd"], ["echo", "hello"])
        self.assertEqual(res["labels"], {"env": "prod", "tier": "api"})


class TestAuditRules(unittest.TestCase):
    def _rule_ids(self, compose_dict):
        return {f.rule_id for f in audit_compose(compose_dict)}

    def test_dc001_privileged(self):
        data = {"services": {"app": {"privileged": True}}}
        self.assertIn("DC001", self._rule_ids(data))

    def test_dc002_host_network(self):
        data = {"services": {"app": {"network_mode": "host"}}}
        self.assertIn("DC002", self._rule_ids(data))

    def test_dc003_docker_sock_string_volume(self):
        data = {"services": {"app": {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}}
        self.assertIn("DC003", self._rule_ids(data))

    def test_dc003_docker_sock_dict_volume(self):
        data = {"services": {"app": {"volumes": [{"type": "bind", "source": "/var/run/docker.sock"}]}}}
        self.assertIn("DC003", self._rule_ids(data))

    def test_dc004_latest_tag(self):
        data = {"services": {"app": {"image": "nginx:latest"}}}
        self.assertIn("DC004", self._rule_ids(data))

    def test_dc004_untagged_image(self):
        data = {"services": {"app": {"image": "postgres"}}}
        self.assertIn("DC004", self._rule_ids(data))

    def test_dc004_pinned_image_passes(self):
        data = {"services": {"app": {"image": "nginx:1.25.3"}}}
        self.assertNotIn("DC004", self._rule_ids(data))

    def test_dc005_hardcoded_secret_dict(self):
        data = {"services": {"app": {"environment": {"DB_PASSWORD": "secret123"}}}}
        self.assertIn("DC005", self._rule_ids(data))

    def test_dc005_hardcoded_secret_list(self):
        data = {"services": {"app": {"environment": ["API_KEY=abc123xyz"]}}}
        self.assertIn("DC005", self._rule_ids(data))

    def test_dc005_env_var_substitution_passes(self):
        data = {"services": {"app": {"environment": {"DB_PASSWORD": "${DB_PASSWORD}"}}}}
        self.assertNotIn("DC005", self._rule_ids(data))

    def test_dc006_missing_restart_policy(self):
        data = {"services": {"app": {"image": "alpine:3.19"}}}
        self.assertIn("DC006", self._rule_ids(data))

    def test_dc006_with_restart_policy_passes(self):
        data = {"services": {"app": {"restart": "unless-stopped"}}}
        self.assertNotIn("DC006", self._rule_ids(data))

    def test_dc007_missing_healthcheck(self):
        data = {"services": {"app": {"image": "alpine:3.19"}}}
        self.assertIn("DC007", self._rule_ids(data))

    def test_dc007_disabled_healthcheck_flags(self):
        data = {"services": {"app": {"healthcheck": {"disable": True}}}}
        self.assertIn("DC007", self._rule_ids(data))

    def test_dc008_missing_resource_limits(self):
        data = {"services": {"app": {"image": "alpine:3.19"}}}
        self.assertIn("DC008", self._rule_ids(data))

    def test_dc008_with_deploy_limits_passes(self):
        data = {
            "services": {
                "app": {
                    "deploy": {"resources": {"limits": {"cpus": "0.5", "memory": "256M"}}}
                }
            }
        }
        self.assertNotIn("DC008", self._rule_ids(data))

    def test_dc009_exposed_db_port(self):
        data = {"services": {"db": {"ports": ["5432:5432"]}}}
        self.assertIn("DC009", self._rule_ids(data))

    def test_dc009_localhost_bound_db_port_passes(self):
        data = {"services": {"db": {"ports": ["127.0.0.1:5432:5432"]}}}
        self.assertNotIn("DC009", self._rule_ids(data))

    def test_dc010_root_user(self):
        data = {"services": {"app": {"user": "root"}}}
        self.assertIn("DC010", self._rule_ids(data))

    def test_dc010_non_root_user_passes(self):
        data = {"services": {"app": {"user": "1000:1000"}}}
        self.assertNotIn("DC010", self._rule_ids(data))

    def test_dc011_host_pid(self):
        data = {"services": {"app": {"pid": "host"}}}
        self.assertIn("DC011", self._rule_ids(data))

    def test_dc012_writable_root_fs(self):
        data = {"services": {"app": {"image": "alpine:3.19"}}}
        self.assertIn("DC012", self._rule_ids(data))


class TestCLIAndFormatters(unittest.TestCase):
    def test_format_text_empty(self):
        out = format_text([], "docker-compose.yml")
        self.assertIn("[PASS]", out)

    def test_format_json_structure(self):
        findings = audit_compose({"services": {"app": {"privileged": True}}})
        payload = json.loads(format_json(findings, "test.yml"))
        self.assertEqual(payload["file"], "test.yml")
        self.assertGreaterEqual(payload["total_findings"], 1)
        self.assertEqual(payload["summary"]["CRITICAL"], 1)

    def test_format_markdown_table(self):
        findings = audit_compose({"services": {"app": {"privileged": True}}})
        md = format_markdown(findings, "test.yml")
        self.assertIn("| Severity | Rule | Service |", md)
        self.assertIn("`DC001`", md)

    def test_should_fail_thresholds(self):
        findings = audit_compose({"services": {"app": {"user": "1000:1000", "read_only": True}}})
        self.assertFalse(should_fail(findings, "high"))
        self.assertFalse(should_fail(findings, "none"))

    def test_cli_missing_file_returns_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["nonexistent-file.yml"])
        self.assertEqual(code, 2)

    def test_cli_insecure_sample_returns_1(self):
        sample = str(SAMPLE_DIR / "insecure-docker-compose.yml")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([sample, "--format", "json", "--fail-on", "high"])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertGreaterEqual(data["total_findings"], 10)

    def test_cli_production_sample_returns_0(self):
        sample = str(SAMPLE_DIR / "production-docker-compose.yml")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([sample, "--fail-on", "low"])
        self.assertEqual(code, 0)
        self.assertIn("[PASS]", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
