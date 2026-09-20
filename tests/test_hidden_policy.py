from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from local_files_mcp.policy import hidden_blocked, hidden_parts_beyond_root, validate


def _cfg(root_path: str, **root_extra) -> dict:
    root = {
        "id": "project",
        "path": root_path,
        "access": "read",
        "allow_extensions": ["*", ".json", ".txt", ".md"],
        "deny_globs": ["**/.env*", "**/.git/**"],
        "write_globs": [],
    }
    root.update(root_extra)
    return {
        "roots": [root],
        "safety": {
            "block_hidden_files": True,
            "allow_hidden_globs": [],
            "block_binary_files": False,
            "allow_symlinks": False,
            "max_file_bytes": 10_000_000,
        },
        "global_deny_globs": [],
    }


class HiddenPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.project = self.base / "AICenter"
        self.data = self.project / ".ai-data" / "bilibili-up" / "subs"
        self.data.mkdir(parents=True)
        (self.data / "clip.json").write_text("{}", encoding="utf-8")
        (self.project / "readme.md").write_text("ok", encoding="utf-8")
        (self.project / ".env").write_text("SECRET=1", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_root_dotdir_is_not_hidden_relative_to_itself(self) -> None:
        hidden_root = self.project / ".ai-data"
        self.assertEqual(hidden_parts_beyond_root(hidden_root, hidden_root), [])
        cfg = _cfg(str(hidden_root))
        decision = validate(cfg, self.data / "clip.json", "read")
        self.assertTrue(decision.allowed, decision.reason)

    def test_hidden_directory_lists_and_reads_like_any_other_folder(self) -> None:
        cfg = _cfg(str(self.project))
        listed = validate(cfg, self.project / ".ai-data", "list")
        self.assertTrue(listed.allowed, listed.reason)
        decision = validate(cfg, self.data / "clip.json", "read")
        self.assertTrue(decision.allowed, decision.reason)
        env = validate(cfg, self.project / ".env", "read")
        self.assertFalse(env.allowed)
        self.assertIn("deny", env.reason.lower())

    def test_allow_hidden_globs_unlocks_ai_data(self) -> None:
        cfg = _cfg(str(self.project))
        cfg["safety"]["allow_hidden_globs"] = ["**/.ai-data/**"]
        decision = validate(cfg, self.data / "clip.json", "read")
        self.assertTrue(decision.allowed, decision.reason)
        env = validate(cfg, self.project / ".env", "read")
        self.assertFalse(env.allowed)

    def test_per_root_allow_hidden(self) -> None:
        cfg = _cfg(str(self.project), allow_hidden=True)
        decision = validate(cfg, self.data / "clip.json", "read")
        self.assertTrue(decision.allowed, decision.reason)
        visible = validate(cfg, self.project / "readme.md", "read")
        self.assertTrue(visible.allowed, visible.reason)


if __name__ == "__main__":
    unittest.main()
