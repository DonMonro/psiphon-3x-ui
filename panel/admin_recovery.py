"""Local admin recovery, invoked by the installed privileged launcher.

The launcher selects the active installation, holds the installer/update lock,
and drops to the panel service account before running this module. Passwords
are accepted only through a hidden terminal prompt, never as command arguments.
No web endpoint exposes this operation.
"""

from __future__ import annotations

import argparse
import getpass
import re
import sqlite3
import sys
import warnings
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from .auth import hash_password, revoke_admin_sessions
from .config import get_settings
from .models import AdminAuthState, Settings

_DB_TIMEOUT_SECONDS = 5.0
_USERNAME = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{2,63}", re.ASCII)


class RecoveryError(Exception):
    """An expected recovery failure that is safe to show in the terminal."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # A mistaken --password argument must not copy a secret into output.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid command arguments. Use --help to see the supported commands.\n")


def _existing_database(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise RecoveryError(
            "The panel database is missing or is not a regular file. "
            "Run this command on the server with the existing panel installation."
        )
    return path.resolve(strict=True)


def _engine(path: Path, *, read_only: bool):
    # mode=rw/ro prevents SQLite from silently creating a new empty database
    # if the installation is missing or the path disappears after validation.
    uri = _existing_database(path).as_uri() + ("?mode=ro" if read_only else "?mode=rw")
    return create_engine(
        "sqlite://",
        creator=lambda: sqlite3.connect(uri, uri=True, timeout=_DB_TIMEOUT_SECONDS),
        poolclass=NullPool,
    )


def _settings(db: Session) -> Settings:
    settings = db.get(Settings, 1)
    if settings is None:
        raise RecoveryError(
            "The panel database has no initialized admin account. "
            "Check the installation before attempting recovery."
        )
    return settings


def read_username(path: Path) -> str:
    """Look up the username without creating tables or changing any state."""
    engine = _engine(path, read_only=True)
    try:
        with Session(engine) as db:
            return _settings(db).admin_user
    finally:
        engine.dispose()


def _display_username(username: str) -> str:
    # The installer previously allowed arbitrary usernames. Escape any
    # terminal controls in a legacy name while displaying ordinary names as is.
    return username if username.isprintable() else ascii(username)


def _validate_username(username: str | None) -> None:
    if username is not None and _USERNAME.fullmatch(username) is None:
        raise RecoveryError(
            "Use 3 to 64 ASCII letters, digits, dots, underscores, or hyphens for the new username."
        )


def _validate_password(password: str) -> None:
    if len(password) < 8:
        raise RecoveryError("The new password must contain at least 8 characters.")
    # bcrypt works on bytes, not characters. Refuse oversize input rather than
    # allowing older bcrypt versions to silently truncate the password.
    if len(password.encode("utf-8")) > 72:
        raise RecoveryError("The new password must fit within 72 UTF-8 bytes.")
    if any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise RecoveryError("The new password must not contain control characters.")


def _prompt_password() -> str:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RecoveryError(
            "A terminal is required for hidden password entry. "
            "Use an interactive SSH session or the server console."
        )
    # getpass otherwise falls back to an echoed stdin prompt when it cannot
    # access a terminal. Treat that warning as a failure before reading input.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("New panel password: ")
            _validate_password(password)
            confirmation = getpass.getpass("Confirm new panel password: ")
        except getpass.GetPassWarning as exc:
            raise RecoveryError("Hidden password entry is unavailable in this terminal.") from exc
    if password != confirmation:
        raise RecoveryError("The passwords do not match. No credentials were changed.")
    return password


def reset_credentials(path: Path, password: str, *, username: str | None = None) -> str:
    """Replace credentials and revoke sessions in one local database transaction."""
    _validate_username(username)
    _validate_password(password)
    # Hash before taking a write lock, so neither typing nor bcrypt blocks
    # normal panel operations. This value is never printed or logged.
    password_hash = hash_password(password)
    engine = _engine(path, read_only=False)
    try:
        with engine.connect() as connection:
            # BEGIN IMMEDIATE serializes concurrent credential writes. Explicit
            # BEGIN also makes additive schema creation transactional on SQLite.
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            with Session(bind=connection) as db:
                settings = _settings(db)
                # Older databases may not yet have booted the updated panel.
                # Add only auth state, never run the installer/seed or create a
                # missing Settings row as part of account recovery.
                AdminAuthState.__table__.create(connection, checkfirst=True)
                settings.admin_pass_hash = password_hash
                if username is not None:
                    settings.admin_user = username
                revoke_admin_sessions(db)
                db.flush()
                recovered_username = settings.admin_user
                connection.commit()
            return recovered_username
    finally:
        engine.dispose()


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _ArgumentParser(
        prog="psiphon-3x-ui-admin", description="Recover the local panel admin account."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Existing panel database (set by the installed launcher).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show-username", help="Show the current panel admin username.")
    reset = commands.add_parser("reset-password", help="Set a new password using a hidden prompt.")
    reset.add_argument(
        "--username",
        default=None,
        help="Also set a new admin username; otherwise keep the current one.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    try:
        database = args.db if args.db is not None else get_settings().db_path
        if args.command == "show-username":
            print(f"Panel admin username: {_display_username(read_username(database))}")
            return 0
        _validate_username(args.username)
        # Check that recovery targets a real account before asking for secrets.
        # Close this read before prompting; never hold a DB lock while typing.
        read_username(database)
        try:
            password = _prompt_password()
        except (EOFError, KeyboardInterrupt):
            print("Recovery cancelled. No credentials were changed.", file=sys.stderr)
            return 130
        username = reset_credentials(database, password, username=args.username)
        print(f"Password reset for panel admin: {_display_username(username)}")
        print("Existing browser sessions are revoked. Return to the login page to sign in.")
        return 0
    except KeyboardInterrupt:
        print(
            "Recovery interrupted. Check the current username and try signing in.", file=sys.stderr
        )
        return 130
    except RecoveryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (OSError, SQLAlchemyError):
        # Database exceptions can contain SQL parameters. Do not include them
        # in terminal output, even when recovery fails after hashing.
        print(
            "Could not access the panel database. Check installation permissions and retry "
            "after any busy database operation has completed. No credentials were changed.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
