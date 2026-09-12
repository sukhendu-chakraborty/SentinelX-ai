"use client";

import { useScroll, useTransform, motion } from "framer-motion";
import React, { useEffect, useRef, useState } from "react";
import { TestSession, TestEvent } from "@/services/testService";
import MachineControl from "./MachineControl";
import CyberBattlefield from "./CyberBattlefield";
import LiveEventConsole from "./LiveEventConsole";

export const STAGES = [
  { id: "s1", name: "Initialization", label: "INPUT", desc: "Machine configuration and environment setup." },
  { id: "s2", name: "Analyze & Discover", label: "DISCOVER", desc: "Mapping the attack surface." },
  { id: "s3", name: "Create Digital Twin", label: "SANDBOX", desc: "Provisioning isolated replica environment." },
  { id: "s4", name: "Multi-Agent Scanning", label: "SCAN", desc: "Swarm deployed for vulnerability discovery." },
  { id: "s5", name: "AI Red Team Attack", label: "ATTACK", desc: "Simulated adversarial exploitation." },
  { id: "s6", name: "AI Blue Team Defense", label: "DEFEND", desc: "Real-time threat mitigation and logging." },
  { id: "s7", name: "Exploit Verification", label: "VERIFY", desc: "Validating exploit success in sandbox." },
  { id: "s8", name: "Self-Healing Engine", label: "HEAL", desc: "Generating algorithmic code patches." },
  { id: "s9", name: "Patch Validation", label: "VALIDATE", desc: "Ensuring patches do not break functionality." },
  { id: "s10", name: "Reports & Integration", label: "REPORT", desc: "Finalizing security audit logs." },
];

export default function SecurityTimeline({
  session,
  events,
  isStarting,
  error,
  onStart
}: {
  session: TestSession | null;
  events: TestEvent[];
  isStarting: boolean;
  error: string | null;
  onStart: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState(0);
  const currentStage = session?.currentStage || 0;
  const status = session?.status || "WAITING";

  useEffect(() => {
    if (ref.current) {
      const rect = ref.current.getBoundingClientRect();
      setHeight(rect.height);
    }
  }, [ref, currentStage, events.length]); // Recalculate if content expands

  useEffect(() => {
    if (currentStage > 1) {
      window.scrollTo({
        top: document.body.scrollHeight,
        behavior: "smooth"
      });
    }
  }, [currentStage]);

  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start 10%", "end 50%"],
  });

  const heightTransform = useTransform(scrollYProgress, [0, 1], [0, height]);
  const opacityTransform = useTransform(scrollYProgress, [0, 0.1], [0, 1]);

  return (
    <div className="w-full bg-ink font-sans pb-32" ref={containerRef}>
      <div className="max-w-7xl mx-auto px-4 md:px-8 lg:px-10 pt-10">
        <h2 className="text-3xl md:text-5xl font-display font-bold uppercase tracking-tight text-fog max-w-4xl">
          Autonomous Security Timeline
        </h2>
        <p className="text-ash text-sm md:text-base max-w-xl mt-4 leading-relaxed">
          The SentinelX AI Swarm continuously discovers, simulates, verifies, and heals application vulnerabilities without risking production downtime.
        </p>
      </div>

      <div ref={ref} className="relative max-w-7xl mx-auto pb-20 mt-16">
        {STAGES.map((item, index) => {
          const isCompleted = currentStage > index + 1 || (currentStage === index + 1 && status === "COMPLETED");
          const isRunning = currentStage === index + 1 && status === "RUNNING";
          const isFailed = currentStage === index + 1 && status === "FAILED";
          const isWaiting = currentStage < index + 1;

          return (
            <div key={index} className="flex justify-start pt-10 md:pt-40 md:gap-10">
              <div className="sticky flex flex-col md:flex-row z-40 items-center top-40 self-start max-w-xs lg:max-w-sm md:w-full">
                <div className="h-10 absolute left-3 md:left-3 w-10 rounded-full bg-panel flex items-center justify-center border border-white/10">
                  <div className={`h-4 w-4 rounded-full border p-2 transition-colors duration-500 ${
                    isRunning ? "bg-lime border-lime shadow-[0_0_15px_#B7FF00] animate-pulse" : 
                    isFailed ? "bg-red-500 border-red-500 shadow-[0_0_15px_#ef4444]" :
                    isCompleted ? "bg-lime border-lime" :
                    "bg-ink border-white/20"
                  }`} />
                </div>
                <div className="hidden md:flex flex-col md:pl-20">
                  <h3 className={`text-xl md:text-4xl lg:text-5xl font-display font-bold uppercase tracking-tight ${
                    isWaiting ? "text-white/20" : isFailed ? "text-red-500" : isCompleted ? "text-lime" : isRunning ? "text-lime" : "text-fog"
                  }`}>
                    {item.name}
                  </h3>
                  <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ash mt-2">
                    {item.label} // {isWaiting ? "WAITING" : isRunning ? "RUNNING" : isFailed ? "FAILED" : "COMPLETED"}
                  </p>
                </div>
              </div>

              <div className="relative pl-20 pr-4 md:pl-4 w-full">
                <h3 className={`md:hidden block text-2xl mb-4 text-left font-display font-bold uppercase tracking-tight ${
                  isWaiting ? "text-white/20" : isFailed ? "text-red-500" : isCompleted ? "text-lime" : isRunning ? "text-lime" : "text-fog"
                }`}>
                  {item.name}
                </h3>
                <p className="text-ash mb-8 text-sm max-w-lg leading-relaxed">
                  {item.desc}
                </p>

                {/* Embedded Content Blocks based on stage */}
                <div className="w-full">
                  {index === 0 && (
                    <div className="w-full max-w-2xl">
                      <MachineControl 
                        session={session} 
                        isStarting={isStarting} 
                        error={error} 
                        onStart={onStart} 
                      />
                    </div>
                  )}

                  {index === 2 && (
                    <div className="w-full max-w-3xl h-[350px]">
                      <LiveEventConsole events={events.filter(e => e.stage <= 3)} />
                    </div>
                  )}

                  {index === 4 && (
                    <div className="w-full max-w-4xl">
                      <CyberBattlefield session={session} events={events} />
                    </div>
                  )}
                  
                  {index === 9 && isFailed && (
                     <div className="border border-red-500/30 bg-red-500/10 p-6">
                        <p className="font-mono text-xs text-red-400 font-bold uppercase tracking-widest mb-2">SYSTEM HALTED</p>
                        <p className="text-sm text-red-400/80">The autonomous loop encountered an unrecoverable backend error. Diagnostics available in telemetry.</p>
                     </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}

        {/* Aceternity SVG Line */}
        <div
          style={{ height: height + "px" }}
          className="absolute md:left-8 left-8 top-0 overflow-hidden w-[2px] bg-[linear-gradient(to_bottom,var(--tw-gradient-stops))] from-transparent from-[0%] via-white/10 to-transparent to-[99%] [mask-image:linear-gradient(to_bottom,transparent_0%,black_10%,black_90%,transparent_100%)]"
        >
          <motion.div
            style={{
              height: heightTransform,
              opacity: opacityTransform,
            }}
            className="absolute inset-x-0 top-0 w-[2px] bg-gradient-to-t from-lime via-lime to-transparent from-[0%] via-[10%] rounded-full shadow-[0_0_15px_#B7FF00]"
          />
        </div>
      </div>
    </div>
  );
}
