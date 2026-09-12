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

export function subscribeToAuditEvents(
  repoUrl: string,
  branch: string = "main",
  onEvent: (event: { event: string; message?: string; data?: any }) => void,
  onError?: (err: any) => void
): () => void {
  const url = `${PYTHON_API_URL}/api/v1/audit/scan/stream?repo_url=${encodeURIComponent(repoUrl)}&branch=${encodeURIComponent(branch)}`;
  const eventSource = new EventSource(url);

  eventSource.onmessage = (e) => {
    try {
      const parsed = JSON.parse(e.data);
      onEvent(parsed);
    } catch (err) {
      console.error("Error parsing SSE event:", err);
    }
  };

  const handleCustomEvent = (eventName: string) => (e: MessageEvent) => {
    try {
      const parsed = JSON.parse(e.data);
      onEvent({ ...parsed, event: eventName });
    } catch (err) {
      console.error(`Error parsing SSE ${eventName} event:`, err);
    }
  };

  eventSource.addEventListener("RECON_STARTED", handleCustomEvent("RECON_STARTED"));
  eventSource.addEventListener("SCANNERS_RUNNING", handleCustomEvent("SCANNERS_RUNNING"));
  eventSource.addEventListener("HEURISTIC_FALLBACK_ENGAGED", handleCustomEvent("HEURISTIC_FALLBACK_ENGAGED"));
  eventSource.addEventListener("AI_TRIAGE_ACTIVE", handleCustomEvent("AI_TRIAGE_ACTIVE"));
  eventSource.addEventListener("REPORT_READY", handleCustomEvent("REPORT_READY"));

  eventSource.onerror = (err) => {
    if (onError) onError(err);
    eventSource.close();
  };

  return () => {
    eventSource.close();
  };
}
