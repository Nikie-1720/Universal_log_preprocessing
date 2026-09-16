from parser import parse


def test_parse():
    result = parse("src=192.0.2.1 dst=198.51.100.1")
    assert result["src"] == "192.0.2.1"
    assert result["dst"] == "198.51.100.1"
