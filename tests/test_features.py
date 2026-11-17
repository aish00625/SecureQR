import numpy as np
import pytest

from secureqr.ml.features import (FEATURE_NAMES, LexicalFeatures, canonicalize_url, legacy_features,
                                  lexical_features, split_host)


@pytest.mark.parametrize("raw,expected", [
    ("https://Example.COM/Path/A", "example.com/Path/A"),
    ("http://example.com", "example.com"),
    ("EXAMPLE.com", "example.com"),
    ("  https://a.b/c  ", "a.b/c"),
    ("ftp://files.example.org/x", "files.example.org/x"),
    (None, ""),
])
def test_canonicalize(raw, expected):
    assert canonicalize_url(raw) == expected


def test_scheme_does_not_change_features():
    """Training data has no scheme; inference must not be skewed by https://."""
    assert lexical_features("https://example.com/a") == lexical_features("example.com/a")
    assert lexical_features("http://example.com/a") == lexical_features("example.com/a")


def test_feature_vector_shape_and_names():
    vec = lexical_features("paypal.com.secure-login.xyz/webscr?cmd=_login&x=1")
    assert len(vec) == len(FEATURE_NAMES) == 30
    named = dict(zip(FEATURE_NAMES, vec))
    assert named["num_subdomains"] == 2
    assert named["num_question"] == 1 and named["num_ampersand"] == 1
    assert named["suspicious_word_count"] >= 3


def test_ip_and_port_and_punycode_features():
    named = dict(zip(FEATURE_NAMES, lexical_features("http://10.0.0.1:8080/x")))
    assert named["is_ip_host"] == 1 and named["has_port"] == 1
    assert dict(zip(FEATURE_NAMES, lexical_features("xn--pypal-4ve.com")))["is_punycode"] == 1
    assert dict(zip(FEATURE_NAMES, lexical_features("bit.ly/abc")))["is_shortener"] == 1


@pytest.mark.parametrize("bad", ["[::1", "a:b:c", "http://[", "%%%", "", "////", "@@@", "a" * 5000])
def test_malformed_urls_never_raise(bad):
    assert len(lexical_features(bad)) == 30
    split_host(canonicalize_url(bad))


def test_transformer_is_stateless_and_log_scaled():
    t = LexicalFeatures()
    out = t.fit_transform(["example.com", "a.b.c.d.example.com/very/long/path"])
    assert out.shape == (2, 30)
    assert np.all(out >= 0)
    assert np.allclose(out, t.transform(["example.com", "a.b.c.d.example.com/very/long/path"]))


def test_legacy_features_match_original_project():
    assert legacy_features("https://a-b.com/1@2") == [len("https://a-b.com/1@2"), 1, 1, 2, 1, 1]
