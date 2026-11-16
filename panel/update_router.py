"""Authenticated update API and installation/mutation arbitration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, StrictBool
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import updates
from .auth import get_current_user

router = APIRouter(dependencies=[Depends(get_current_user)])


class CheckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DownloadBody(CheckBody):
    revision: updates.Revision


class InstallBody(CheckBody):
    job_id: updates.JobID
    confirm: StrictBool


async def _result(operation, response: Response) -> dict:
    response.headers["Cache-Control"] = "no-store"
    try:
        result = await operation
    except updates.UpdateError as exc:
        raise HTTPException(
            exc.status_code, str(exc), headers={"Cache-Control": "no-store"}
        ) from exc
    response.status_code = 202 if result["phase"] in {"downloading", "installing"} else 200
    return result


@router.get("")
async def update_status(response: Response) -> dict:
    result = await _result(updates.get_manager().status(), response)
    response.status_code = 200
    return result


@router.post("/check")
async def check_updates(body: CheckBody, response: Response) -> dict:
    return await _result(updates.get_manager().check(download=True), response)


@router.post("/download")
async def download_update(body: DownloadBody, response: Response) -> dict:
    return await _result(updates.get_manager().download(body.revision), response)


@router.post("/install")
async def install_update(body: InstallBody, response: Response) -> dict:
    if body.confirm is not True:
        raise HTTPException(
            status_code=400,
            detail="Explicit installation confirmation is required.",
            headers={"Cache-Control": "no-store"},
        )
    return await _result(updates.get_manager().install(body.job_id, body.confirm), response)


class UpdateMaintenanceMiddleware:
    """Hold mutation reservations through the complete ASGI response lifetime.

    BaseHTTPMiddleware's call_next returns before an SSE stream finishes. This
    outer ASGI layer releases only after the stream and background work finish,
    so a second browser cannot install while wizard apply/clone is still busy.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        mutation = scope["type"] == "http" and scope["method"] in {"POST", "PUT", "PATCH", "DELETE"}
        # Update actions arbitrate on the same state lock internally. In
        # particular the install request must not count as its own blocker.
        path = scope.get("path", "").rstrip("/")
        update_action = path in {
            "/api/updates/check",
            "/api/updates/download",
            "/api/updates/install",
        }
        # Session cookies do not alter installed panel state. Keep sign-in and
        # sign-out available so an expired session can inspect update recovery.
        session_action = path in {"/auth/login", "/auth/logout"}
        if not mutation or update_action or session_action:
            await self.app(scope, receive, send)
            return
        manager = updates.get_manager()
        try:
            await manager.begin_mutation()
        except updates.UpdateError as exc:
            await JSONResponse(
                {"detail": str(exc)},
                status_code=exc.status_code,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            manager.end_mutation()
