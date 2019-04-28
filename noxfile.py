import nox

@nox.session
def test(session):

    session.install("-r", "requirements-test.txt")
    session.install(".")

    session.run("pytest")
