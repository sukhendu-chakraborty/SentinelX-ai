import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from schemas.remediation import RemediationRequest, RemediationReport
from services.blue_team_agents import execute_remediation_pipeline

router = APIRouter(prefix="/api/v1/remediation", tags=["Blue Team Remediation"])

@router.post("/patch", response_model=RemediationReport)
async def generate_remediation_patches(request: RemediationRequest):
    """
    Accepts verified vulnerability findings, applies physical file patches to disk,
    commits changes to a Git branch, and returns the RemediationReport.
    """
    report_data = None
    async for event in execute_remediation_pipeline(
        findings=request.findings,
        repo_path=request.repo_path,
        auto_apply=request.auto_apply,
        create_git_branch=request.create_git_branch,
        branch_name=request.branch_name
    ):
        if event.get("event") == "REMEDIATION_REPORT_READY":
            report_data = event.get("data")

    if not report_data:
        raise HTTPException(status_code=500, detail="Remediation pipeline failed to generate report.")

    return RemediationReport(**report_data)

@router.post("/stream")
async def stream_remediation_patches(request: RemediationRequest):
    """
    SSE endpoint broadcasting real-time Blue Team physical file modification and Git commit milestones.
    """
    async def event_generator():
        async for event in execute_remediation_pipeline(
            findings=request.findings,
            repo_path=request.repo_path,
            auto_apply=request.auto_apply,
            create_git_branch=request.create_git_branch,
            branch_name=request.branch_name
        ):
            data_str = json.dumps(event)
            yield f"data: {data_str}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
