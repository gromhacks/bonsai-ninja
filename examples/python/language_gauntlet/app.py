"""Conventional Flask launcher for the nested language gauntlet package."""

from entrypoints.http import app


if __name__ == "__main__":
    app.run()
