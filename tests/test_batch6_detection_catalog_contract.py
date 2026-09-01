from scripts.verify_detection_catalog import EXPECTED_DATASETS, EXPECTED_RULES


def test_batch6_detection_catalog_expected_datasets_include_entra() -> None:
    assert EXPECTED_DATASETS["entra_id"] == 4
    assert sum(EXPECTED_DATASETS.values()) == EXPECTED_RULES == 46