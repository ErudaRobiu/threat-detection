"use client";

import { useEffect, useState } from "react";

/**
 * Header telemetry: a live HH:MM:SS clock and a "SYSTEM ONLINE" status pill.
 * The clock is client-only (it ticks); rendered empty on the server so there is
 * no hydration mismatch, then filled on mount.
 */
export default function SystemStatus() {
  const [clock, setClock] = useState("");

  useEffect(() => {
    const p = (n: number) => String(n).padStart(2, "0");
    const tick = () => {
      const d = new Date();
      setClock(`${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <>
      <div className="sys-pill">
        <span className="sys-dot" aria-hidden="true" />
        SYSTEM ONLINE
      </div>
      <div className="sys-clock mono" suppressHydrationWarning>
        {clock}
      </div>
    </>
  );
}
