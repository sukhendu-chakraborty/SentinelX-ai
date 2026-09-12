"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Swords, ShieldCheck } from "lucide-react";
import { TestSession, TestEvent } from "@/services/testService";

// Helper component for the laser shots, same as Battle.tsx but driven by real events
const LaserEffects = ({ feed }: { feed: TestEvent[] }) => {
  const [shots, setShots] = useState<TestEvent[]>([]);

  useEffect(() => {
    if (!feed.length) return;
    const latest = feed[feed.length - 1]; // Assume feed is appended
    setShots((s) => [...s, latest].slice(-5));
  }, [feed]);

  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden z-20">
      {shots.map((shot, idx) => {
        // We guess side based on type or stage if not explicitly provided
        const isRed = shot.type === "error" || shot.stage === 5;
        const color = isRed ? "#FF5F56" : "#B7FF00";

        return (
          <motion.div
            key={`${shot.id}-${idx}`}
            initial={{ left: isRed ? "-20%" : "120%" }}
            animate={{ left: isRed ? "120%" : "-20%" }}
            transition={{ duration: 0.45, ease: "linear" }}
            className="absolute top-1/2 -translate-y-1/2 w-[300px]"
          >
            <svg width="300" height="60" viewBox="0 0 300 60" className={`overflow-visible ${isRed ? "" : "-scale-x-100"}`}>
              <path d="M 0 30 L 260 30" stroke={color} strokeWidth="6" style={{ filter: "blur(4px)" }} />
              <path d="M 100 30 L 280 30" stroke="#fff" strokeWidth="2" />
              <path d="M 250 15 L 300 30 L 250 45 Z" fill="#fff" style={{ filter: `drop-shadow(0 0 15px ${color})` }} />
              <path d="M 230 0 L 280 30 L 230 60" stroke={color} strokeWidth="3" fill="none" style={{ filter: "blur(2px)" }} />
              <path d="M 260 10 L 290 30 L 260 50" stroke="#fff" strokeWidth="2" fill="none" />
            </svg>
          </motion.div>
        );
      })}
    </div>
  );
};

export default function CyberBattlefield({
  session,
  events,
}: {
  session: TestSession | null;
  events: TestEvent[];
}) {
  const isRunning = session?.status === "RUNNING";
  
  // Filter events to only show stage 4-9 (Attack/Defend stages)
  const battleEvents = events.filter(e => e.stage >= 4 && e.stage <= 9);

  return (
    <div className="border border-white/10 bg-[#0D0F0D] rounded-xl overflow-hidden relative">
      <div className="relative z-10 grid grid-cols-3 border-b border-white/10 bg-black/40">
        <div className="p-5 flex items-center gap-3 border-r border-white/10">
          <Swords size={16} className="text-[#FF5F56]" />
          <div>
            <p className="font-mono text-[10px] tracking-[0.25em] text-[#FF5F56]">RED TEAM</p>
            <p className="font-mono text-[9px] text-slate-500 mt-0.5">ATTACK</p>
          </div>
        </div>
        <div className="p-5 text-center border-r border-white/10 flex flex-col items-center justify-center">
          <p className="font-mono text-[10px] tracking-[0.25em] text-slate-300 flex items-center justify-center gap-2 bg-black/60 px-3 py-1 rounded-full border border-white/10">
            {isRunning ? (
               <><span className="w-1.5 h-1.5 rounded-full bg-lime animate-pulse" /> LIVE BATTLE</>
            ) : (
               <><span className="w-1.5 h-1.5 rounded-full bg-slate-500" /> STANDBY</>
            )}
          </p>
        </div>
        <div className="p-5 flex items-center justify-end gap-3">
          <div className="text-right">
            <p className="font-mono text-[10px] tracking-[0.25em] text-lime">BLUE TEAM</p>
            <p className="font-mono text-[9px] text-slate-500 mt-0.5">DEFEND</p>
          </div>
          <ShieldCheck size={16} className="text-lime" />
        </div>
      </div>

      <div className="relative bg-[#050505]">
        <LaserEffects feed={battleEvents} />
        
        <div 
          className="relative p-6 md:p-8 h-[380px] font-mono text-xs md:text-sm space-y-3 overflow-hidden flex flex-col-reverse"
          style={{ maskImage: "linear-gradient(to bottom, transparent 0%, black 20%, black 100%)", WebkitMaskImage: "linear-gradient(to bottom, transparent 0%, black 20%, black 100%)" }}
        >
          <AnimatePresence initial={false}>
            {battleEvents.length === 0 && !isRunning && (
              <div className="absolute inset-0 flex items-center justify-center text-slate-600 font-mono text-xs z-10">
                Awaiting autonomous execution...
              </div>
            )}
            {/* Reverse the array visually since flex-col-reverse puts the first item at the bottom */}
            {[...battleEvents].reverse().map((ev, idx) => {
              const isRed = ev.type === "error" || ev.stage === 5;
              
              return (
                <motion.div
                  key={`${ev.id}-${idx}`}
                  initial={{ opacity: 0, x: isRed ? -20 : 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.25, ease: "easeOut" }}
                  className={`relative z-10 flex gap-4 ${!isRed ? "justify-end" : ""}`}
                >
                  {isRed && <span className="text-slate-500 text-[10px] pt-1 shrink-0">{ev.timestamp}</span>}
                  <span
                    className={`px-3 py-1.5 border max-w-md backdrop-blur-md ${isRed
                        ? "border-[#FF5F56]/30 text-[#FF8A80] bg-[#FF5F56]/10"
                        : "border-lime/30 text-lime bg-lime/10"
                      }`}
                  >
                    <span className="text-[9px] tracking-[0.2em] mr-2 opacity-60">
                      {isRed ? "ATTACK" : "DEFEND"}
                    </span>
                    {ev.message}
                  </span>
                  {!isRed && <span className="text-slate-500 text-[10px] pt-1 shrink-0">{ev.timestamp}</span>}
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
