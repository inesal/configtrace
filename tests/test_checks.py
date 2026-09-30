from pathlib import Path
import tempfile
import unittest

from configtrace.checks import run_checks


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples" / "demo"


class ConfigTraceTests(unittest.TestCase):
    def test_demo_references_are_connected(self):
        self.assertEqual(run_checks(DEMO), [])

    def test_missing_vault_variable_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / "ansible").mkdir()
            (project / "deploy").mkdir()
            (project / "configtrace.yml").write_text(
                "ansible: ansible/vars.yml\ntemplate: deploy/app.env.j2\ncompose: deploy/compose.yml\nservice: api\n",
                encoding="utf-8",
            )
            (project / "ansible" / "vars.yml").write_text(
                "other_password: \"{{ lookup('hashi_vault', 'secret=secret/data/demo:password') }}\"\n",
                encoding="utf-8",
            )
            (project / "deploy" / "app.env.j2").write_text("API_PASSWORD={{ api_password }}\n", encoding="utf-8")
            (project / "deploy" / "compose.yml").write_text(
                "services:\n  api:\n    environment:\n      API_PASSWORD: ${API_PASSWORD}\n",
                encoding="utf-8",
            )
            codes = {item.code for item in run_checks(project)}
            self.assertIn("VAULT_SOURCE_MISSING", codes)

    def test_missing_external_secret_key_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            for folder in ("ansible", "deploy", "k8s"):
                (project / folder).mkdir(parents=True, exist_ok=True)
            (project / "configtrace.yml").write_text(
                "ansible: ansible/vars.yml\ntemplate: deploy/app.env.j2\ncompose: deploy/compose.yml\nservice: api\nkubernetes:\n  - k8s/external.yml\n  - k8s/deployment.yml\n",
                encoding="utf-8",
            )
            (project / "ansible" / "vars.yml").write_text(
                "api_password: \"{{ lookup('hashi_vault', 'secret=secret/data/demo:password') }}\"\n",
                encoding="utf-8",
            )
            (project / "deploy" / "app.env.j2").write_text("API_PASSWORD={{ api_password }}\n", encoding="utf-8")
            (project / "deploy" / "compose.yml").write_text(
                "services:\n  api:\n    environment:\n      API_PASSWORD: ${API_PASSWORD}\n",
                encoding="utf-8",
            )
            (project / "k8s" / "external.yml").write_text(
                "kind: ExternalSecret\nmetadata:\n  name: api-credentials\nspec:\n  target:\n    name: api-credentials\n  data:\n    - secretKey: OTHER_KEY\n",
                encoding="utf-8",
            )
            (project / "k8s" / "deployment.yml").write_text(
                "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - env:\n            - valueFrom:\n                secretKeyRef:\n                  name: api-credentials\n                  key: API_PASSWORD\n",
                encoding="utf-8",
            )
            codes = {item.code for item in run_checks(project)}
            self.assertIn("EXTERNAL_SECRET_KEY_MISSING", codes)

    def test_yaml_error_does_not_echo_file_content(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / "configtrace.yml").write_text("secret: [SYNTHETIC_SECRET_VALUE\n", encoding="utf-8")
            with self.assertRaises(ValueError) as raised:
                run_checks(project)
            self.assertNotIn("SYNTHETIC_SECRET_VALUE", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
