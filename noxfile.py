import nox

# All of the cool stuff in here (like black and flake8, and the sphinx setup) is based on nox's own noxfile


@nox.session
def test(session):

    session.install("-r", "requirements-test.txt")
    session.install(".")

    session.run("pytest")


@nox.session(py="3.6")
def black(session):

    session.install("black")

    session.run(
        "black",
        "encrypted_stream.py",
        "test_encrypted_stream.py",
        "setup.py",
        "noxfile.py",
    )


@nox.session(reuse_venv=True)
def docs(session):

    session.install("sphinx")

    session.cd("docs")
    session.run("rm", "-r", "_build", external=True)
    session.run(*("sphinx-build -b html . _build/html".split(" ")))
