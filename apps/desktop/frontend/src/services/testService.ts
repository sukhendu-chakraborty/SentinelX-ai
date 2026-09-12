import { Project } from "@/types/github";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081";
const PYTHON_API_URL = process.env.NEXT_PUBLIC_PYTHON_API_URL || "http://localhost:8000";

export interface TestSession {
  id: string;
  projectId: string;
  status: "WAITING" | "RUNNING" | "COMPLETED" | "FAILED";
  currentStage: number;
  message?: string;
}

export interface TestEvent {
  id: string;
  timestamp: string;
  stage: number;
  message: string;
  type: "info" | "success" | "error" | "warning";
}

export async function fetchProjectDetails(projectId: string): Promise<Project | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    });

    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }

    const projects: Project[] = await response.json();
    return projects.find((p) => p.id === projectId) || null;
  } catch (error) {
    console.error("Failed to fetch project details:", error);
    return null;
  }
}

export async function startProjectTest(projectId: string): Promise<TestSession> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/test/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    return await response.json();
  } catch (error: any) {
    throw new Error(error.message || "Failed to start machine");
  }
}

export async function fetchTestStatus(projectId: string): Promise<TestSession | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/test/status`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    });

    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    return null;
  }
}

export function startRealAuditStream(repoUrl: string, branch: string, onEvent: (event: any) => void, onError: (err: any) => void, onComplete: () => void): EventSource {
  const url = `${PYTHON_API_URL}/api/v1/audit/scan/stream?repo_url=${encodeURIComponent(repoUrl)}&branch=${encodeURIComponent(branch)}`;
  const eventSource = new EventSource(url);

  eventSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.event === "REPORT_READY") {
        onEvent(data);
        eventSource.close();
        onComplete();
      } else {
        onEvent(data);
      }
    } catch (err) {
      console.error("Failed to parse SSE JSON:", err);
    }
  };

  eventSource.onerror = (err) => {
    onError(err);
    eventSource.close();
  };

  return eventSource;
}

export async function startRealRemediationStream(findings: any[], repoPath: string, onEvent: (event: any) => void) {
  const url = `${PYTHON_API_URL}/api/v1/remediation/stream`;
  
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        findings,
        repo_path: repoPath,
        auto_apply: false,
        create_git_branch: false,
        branch_name: "sentinelx/security-patches"
      }),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (!response.body) throw new Error("No response body");

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop() || "";

      for (const chunk of lines) {
        if (!chunk.trim()) continue;
        const dataLine = chunk.split("\n").find(l => l.startsWith("data: "));
        if (dataLine) {
          try {
            const dataStr = dataLine.replace("data: ", "");
            const parsed = JSON.parse(dataStr);
            onEvent(parsed);
          } catch (e) {
            console.error("Failed parsing stream chunk", e);
          }
        }
      }
    }
  } catch (error) {
    console.error("Remediation stream error:", error);
    throw error;
  }
}
