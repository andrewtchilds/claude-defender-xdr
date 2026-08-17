/** Keeps a single tool result well inside the model's context budget. */
export const MAX_OUTPUT_BYTES = 50 * 1024;

export const TRUNCATION_NOTICE =
  "\n\n[Output truncated; refine the query or explicitly request export_results.]";

/**
 * Serializes a payload, trimming to a whole number of UTF-8 characters when it is too
 * large. Truncated output is deliberately left as invalid JSON with an explicit notice so
 * a prefix is never mistaken for a complete result set.
 */
export function bounded(value: unknown, maxBytes = MAX_OUTPUT_BYTES): string {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  const decoder = new TextDecoder("utf8", { fatal: false, ignoreBOM: true });
  const head = decoder.decode(Buffer.from(text, "utf8").subarray(0, maxBytes));
  // Drop a trailing replacement character produced by cutting mid-codepoint.
  return `${head.replace(/�$/, "")}${TRUNCATION_NOTICE}`;
}

/** Graph annotates typed values with sibling `<field>@odata.type` keys that carry no signal. */
export function stripODataAnnotations(row: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(row).filter(([key]) => !key.endsWith("@odata.type")));
}
