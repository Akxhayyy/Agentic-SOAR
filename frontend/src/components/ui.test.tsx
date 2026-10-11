import { render } from "@testing-library/react";
import { LogViewer, Markdown, statusKey } from "./ui";
import { clock, hitlRemaining, vectorLabel } from "../lib/format";

// THREAT_MODEL.md T8: log text and LLM report text are attacker-influenced and
// must never become live HTML in the operator's browser.
describe("untrusted content rendering", () => {
  const payload = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>`;

  it("LogViewer renders log lines as text, never HTML", () => {
    const { container } = render(
      <LogViewer lines={[`user admin ${payload}`]} iocs={[{ ioc_type: "USERNAME", value: "admin", confidence: 1 }]} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>");
    expect(container.querySelector("mark")?.textContent).toBe("admin");
  });

  it("Markdown does not pass raw HTML through", () => {
    const { container } = render(<Markdown>{`# Report\n\n${payload}\n\n[click](javascript:alert(1))`}</Markdown>);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("a")).toBeNull(); // links are rendered as inert text
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("LogViewer escapes regex metacharacters in IOC values", () => {
    const { container } = render(
      <LogViewer lines={["host a.b+c(1) seen"]} iocs={[{ ioc_type: "HOSTNAME", value: "a.b+c(1)", confidence: 1 }]} />,
    );
    expect(container.querySelector("mark")?.textContent).toBe("a.b+c(1)");
  });
});

describe("status + formatting", () => {
  it("derives a display status", () => {
    expect(statusKey({ awaiting_hitl: true, threat_status: "OPEN" })).toBe("AWAITING");
    expect(statusKey({ current_phase: "FAILED", threat_status: "ESCALATED" })).toBe("FAILED");
    expect(statusKey({ current_phase: "TRIAGED", threat_status: "OPEN" })).toBe("RUNNING");
    expect(statusKey({ current_phase: "REPORTED", threat_status: "CONTAINED" })).toBe("CONTAINED");
  });

  it("computes the HITL countdown from the persisted pause time", () => {
    const paused = new Date(Date.now() - 100_000).toISOString();
    const left = hitlRemaining(paused, 300)!;
    expect(left).toBeGreaterThan(198);
    expect(left).toBeLessThan(201);
    expect(hitlRemaining(null, 300)).toBeNull();
    expect(clock(125)).toBe("2:05");
    expect(vectorLabel("BRUTE_FORCE_AUTH")).toBe("Brute force");
  });
});
