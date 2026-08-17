import { describe, expect, it } from "vitest";
import { normalizeTimespan } from "../server/client.js";
import { bounded, stripODataAnnotations, TRUNCATION_NOTICE } from "../server/output.js";

describe("normalizeTimespan", () => {
  it("expands the shorthand the skills use", () => {
    expect(normalizeTimespan("7d")).toBe("P7D");
    expect(normalizeTimespan("24h")).toBe("PT24H");
    expect(normalizeTimespan(" 30d ")).toBe("P30D");
  });

  it("passes through ISO-8601 durations, normalized to upper case", () => {
    expect(normalizeTimespan("p7d")).toBe("P7D");
    expect(normalizeTimespan("PT30M")).toBe("PT30M");
    expect(normalizeTimespan("P1DT12H")).toBe("P1DT12H");
  });

  it("rejects anything else rather than sending it to Graph", () => {
    for (const bad of ["forever", "", "7", "d7", "P", "PT", "7 days", "P7D; drop"]) {
      expect(() => normalizeTimespan(bad), bad).toThrow("timespan");
    }
  });
});

describe("bounded", () => {
  it("returns exact JSON when the payload fits", () => {
    const payload = { totalRows: 1, results: [{ DeviceId: "abc" }] };
    expect(JSON.parse(bounded(payload))).toEqual(payload);
  });

  it("marks oversized payloads instead of silently returning a prefix", () => {
    const text = bounded({ results: ["x".repeat(5000)] }, 256);
    expect(text.endsWith(TRUNCATION_NOTICE)).toBe(true);
    expect(() => JSON.parse(text)).toThrow();
  });

  it("never emits a broken UTF-8 sequence when cutting mid-codepoint", () => {
    // "🛡" is four UTF-8 bytes, so most cut points land inside a character.
    for (let limit = 20; limit < 40; limit++) {
      const text = bounded({ results: ["🛡".repeat(200)] }, limit);
      const head = text.slice(0, -TRUNCATION_NOTICE.length);
      expect(head.includes("�"), `limit ${limit}`).toBe(false);
    }
  });
});

describe("stripODataAnnotations", () => {
  it("drops Graph type annotations but keeps every data column", () => {
    expect(
      stripODataAnnotations({
        Timestamp: "2026-01-01T00:00:00Z",
        "Timestamp@odata.type": "#DateTimeOffset",
        DeviceId: "abc",
      }),
    ).toEqual({ Timestamp: "2026-01-01T00:00:00Z", DeviceId: "abc" });
  });

  it("leaves a column whose name merely contains the marker", () => {
    const row = { "odata.type": "kept", Notes: "@odata.type in text" };
    expect(stripODataAnnotations(row)).toEqual(row);
  });
});
