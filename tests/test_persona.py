from urllib.parse import urlsplit

from demo import persona


def test_persona_visits_only_public_https_pages():
    assert len(persona.VISITS) >= 10
    for v in persona.VISITS:
        p = urlsplit(v.url)
        assert p.scheme == "https" and p.hostname and not p.username
        assert not p.query or "q=" not in p.query  # no search terms in the persona either


def test_persona_never_fills_forms_or_logs_in():
    for v in persona.VISITS:
        assert set(v.actions) <= {"scroll", "wait", "click_first_article"}


def test_persona_runs_in_a_fresh_profile():
    assert persona.LAUNCH_OPTIONS["persistent"] is False
