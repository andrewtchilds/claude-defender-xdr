import { describe, expect, it } from "vitest";
import { normalizeTimespan } from "../src/graph.js";

describe("normalizeTimespan", () => {
  it("converts the shorthand the skills use into ISO-8601", () => {
    expect(normalizeTimespan("7d")).toBe("P7D");
    expect(normalizeTimespan("24h")).toBe("PT24H");
    expect(normalizeTimespan(" 30 d ")).toBe("P30D");
  });

  it("passes ISO-8601 durations through", () => {
    expect(normalizeTimespan("P7D")).toBe("P7D");
    expect(normalizeTimespan("pt24h")).toBe("PT24H");
  });

  it("rejects anything else with the accepted forms in the message", () => {
    expect(() => normalizeTimespan("last week")).toThrow(/7d, 24h, P7D, or PT24H/);
    expect(() => normalizeTimespan("")).toThrow();
    expect(() => normalizeTimespan("7")).toThrow();
  });
});
