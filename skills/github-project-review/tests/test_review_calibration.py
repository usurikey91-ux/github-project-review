import re
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SKILL_TEXT = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
CALIBRATION_TEXT = (SKILL_ROOT / "references" / "review-calibration.md").read_text(
    encoding="utf-8"
)


class ReviewCalibrationTests(unittest.TestCase):
    def test_skill_requires_shape_adjusted_calibration(self):
        self.assertIn("references/review-calibration.md", SKILL_TEXT)
        self.assertIn("项目形态必须实际改变证据权重", SKILL_TEXT)

    def test_skill_separates_material_risks_from_quality_issues(self):
        for tier in ("阻断风险", "实质约束", "工程质量问题", "证据缺口"):
            self.assertIn(tier, SKILL_TEXT)
        self.assertIn("若只有普通工程质量问题", SKILL_TEXT)

    def test_regression_cases_cover_expected_failure_modes(self):
        case_ids = re.findall(r"<!-- case: ([a-z0-9-]+) -->", CALIBRATION_TEXT)
        self.assertEqual(
            case_ids,
            [
                "agent-skill-complete-no-release",
                "agent-skill-noncore-cache-defect",
                "polished-readme-no-implementation",
                "desktop-unsafe-installer",
                "self-hosted-real-operations",
                "library-old-but-stable",
            ],
        )

    def test_agent_skill_cases_do_not_promote_weak_signals(self):
        self.assertRegex(
            CALIBRATION_TEXT,
            r"完整 Agent Skill，没有 Release[\s\S]+推荐采用[\s\S]+不能成为最大风险",
        )
        self.assertRegex(
            CALIBRATION_TEXT,
            r"非核心缓存缺陷[\s\S]+功能真实[\s\S]+写入“主要不足”",
        )

    def test_high_impact_cases_keep_strong_recommendations(self):
        self.assertRegex(
            CALIBRATION_TEXT,
            r"漂亮 README，没有核心实现[\s\S]+疑似空架子[\s\S]+不建议采用",
        )
        self.assertRegex(
            CALIBRATION_TEXT,
            r"桌面应用要求关闭安全防护[\s\S]+高风险信号[\s\S]+不建议采用",
        )


if __name__ == "__main__":
    unittest.main()
