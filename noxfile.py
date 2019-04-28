import nox

# All of the cool stuff in here (like black and flake8) comes from nox's own noxfile


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
