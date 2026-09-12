"use client";

import { useEffect, useState } from "react";
import { fetchProjectDetails, fetchTestStatus, startProjectTest, TestSession, TestEvent, startRealAuditStream, startRealRemediationStream } from "@/services/testService";
import { Project } from "@/types/github";
import WorkspaceHeader from "./WorkspaceHeader";
import SecurityTimeline from "./SecurityTimeline";
import gsap from "gsap";

export default function TestWorkspace({ projectId }: { projectId: string }) {
  const [project, setProject] = useState<Project | null>(null);
  const [session, setSession] = useState<TestSession | null>(null);
  const [events, setEvents] = useState<TestEvent[]>([]);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Real AI Data State
  const [realVulnerabilities, setRealVulnerabilities] = useState<any[]>([]);
  const [realPatches, setRealPatches] = useState<any[]>([]);
  const [realDevNotes, setRealDevNotes] = useState<any[]>([]);
  const [telemetryEvents, setTelemetryEvents] = useState<any[]>([]);

  // Initial load
  useEffect(() => {
    async function load() {
      const p = await fetchProjectDetails(projectId);
      setProject(p);
      
      const s = await fetchTestStatus(projectId);
      if (s) setSession(s);
    }
    load();
    
    gsap.fromTo(
      ".workspace-animate-in",
      { opacity: 0, y: 20 },
      { opacity: 1, y: 0, duration: 0.6, stagger: 0.1, ease: "power3.out" }
    );
  }, [projectId]);

  const addEvent = (msg: string, type: "info" | "success" | "error" | "warning", stage: number) => {
    setEvents((prev) => [
      ...prev,
      {
        id: `ev-${Date.now()}-${Math.random()}`,
        timestamp: new Date().toTimeString().slice(0, 8),
        stage,
        message: msg,
        type
      },
    ]);
  };

  const handleStartMachine = async () => {
    if (!project) return;
    setIsStarting(true);
    setError(null);
    setEvents([]);
    setRealVulnerabilities([]);
    setRealPatches([]);
    setRealDevNotes([]);
    setTelemetryEvents([]);
    
    addEvent("Initializing SentinelX environment...", "info", 1);
    
    try {
      const newSession = await startProjectTest(projectId);
      setSession(newSession);
      addEvent("Environment established. Connecting to AI Engine...", "success", 1);

      let currentFindings: any[] = [];

      startRealAuditStream(
        project.htmlUrl,
        project.defaultBranch || "main",
        (sseEvent: any) => {
          const type = sseEvent.event;
          const msg = sseEvent.message || type;
          
          if (type === "RECON_STARTED") {
            setSession(s => s ? { ...s, currentStage: 2, status: "RUNNING" } : null);
            addEvent(msg, "info", 2);
          } else if (type === "SCANNERS_RUNNING") {
            setSession(s => s ? { ...s, currentStage: 4, status: "RUNNING" } : null);
            addEvent(msg, "info", 4);
          } else if (type === "AI_TRIAGE_ACTIVE") {
            addEvent(msg, "info", 4);
          } else if (type === "TELEMETRY_PROBE") {
            setSession(s => s ? { ...s, currentStage: 5, status: "RUNNING" } : null);
            setTelemetryEvents(prev => [...prev, sseEvent.data]);
            const statusType = sseEvent.data.status === "EXPLOIT_VERIFIED" ? "error" : "warning";
            addEvent(`Probe [${sseEvent.data.vector}] on ${sseEvent.data.target_endpoint}: ${sseEvent.data.status}`, statusType, 5);
          } else if (type === "REPORT_READY") {
            setSession(s => s ? { ...s, currentStage: 6, status: "RUNNING" } : null);
            currentFindings = sseEvent.data.verified_vulnerabilities || [];
            setRealVulnerabilities(currentFindings);
            addEvent(`Audit Complete: ${currentFindings.length} vulnerabilities found. Handing off to Blue Team.`, "success", 6);
          } else {
             addEvent(msg, "info", session?.currentStage || 2);
          }
        },
        (err) => {
          setError("Audit stream disconnected.");
          setSession(s => s ? { ...s, status: "FAILED" } : null);
          addEvent("Error connecting to AI Audit Engine.", "error", session?.currentStage || 1);
        },
        () => {
          if (currentFindings.length === 0) {
            setSession(s => s ? { ...s, currentStage: 10, status: "COMPLETED" } : null);
            addEvent("No vulnerabilities to remediate. Sandbox disengaged.", "success", 10);
            return;
          }
          
          setSession(s => s ? { ...s, currentStage: 7, status: "RUNNING" } : null);
          addEvent("Blue Team initiating AI Patch Generation...", "info", 7);
          
          startRealRemediationStream(currentFindings, project.htmlUrl, (remEvent: any) => {
            const rType = remEvent.event;
            const rMsg = remEvent.message || rType;
            
            if (rType === "REMEDIATION_STARTED") {
              addEvent(rMsg, "info", 7);
            } else if (rType === "RULE_BASED_FALLBACK_ENGAGED") {
              addEvent(remEvent.data, "warning", 8);
            } else if (rType === "REMEDIATION_REPORT_READY") {
              const patches = remEvent.data.patches || [];
              setRealPatches(patches);
              
              const notes = patches.map((p: any) => ({
                id: p.finding_id,
                vulnTitle: p.file_path,
                cwe: p.cwe_id,
                filePath: p.file_path,
                rootCause: p.developer_note?.root_cause || "N/A",
                remediationApplied: p.developer_note?.remediation_applied || "N/A",
                verificationSteps: p.developer_note?.verification_steps || "N/A",
                status: p.syntax_valid ? "VERIFIED_IN_TWIN" : "FAILED"
              }));
              setRealDevNotes(notes);
              
              addEvent(`Patch Validation Complete. ${remEvent.data.total_successful}/${remEvent.data.total_attempted} patches generated successfully.`, "success", 9);
              
              setSession(s => s ? { ...s, currentStage: 10, status: "COMPLETED" } : null);
              addEvent("All tasks complete. Digital Twin sandbox disengaged.", "success", 10);
            } else {
              addEvent(rMsg, "info", 8);
            }
          }).catch(err => {
             setError("Remediation stream disconnected.");
             setSession(s => s ? { ...s, status: "FAILED" } : null);
             addEvent("Error connecting to AI Remediation Engine.", "error", 8);
          });
        }
      );
      
    } catch (err: any) {
      setError(err.message || "Failed to start machine.");
      addEvent(`System Error: ${err.message}`, "error", 0);
      setSession({
        id: "err",
        projectId,
        status: "FAILED",
        currentStage: 0,
      });
    } finally {
      setIsStarting(false);
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      <div className="workspace-animate-in w-full max-w-7xl mx-auto px-4 md:px-8 mt-4 md:mt-8">
        <WorkspaceHeader project={project} isConnected={true} />
      </div>

      <div className="flex-1 w-full workspace-animate-in">
        <SecurityTimeline 
          session={session} 
          events={events}
          isStarting={isStarting}
          error={error}
          onStart={handleStartMachine}
          realVulnerabilities={realVulnerabilities}
          realPatches={realPatches}
          realDevNotes={realDevNotes}
          telemetryEvents={telemetryEvents}
        />
      </div>
    </div>
  );
}
