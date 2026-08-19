---
name: defender-xdr-messaging-investigation
description: Investigates Defender XDR email and Teams threats. Use for phishing, attachments, URLs, delivery or remediation, Safe Links clicks, campaigns, sender or domain pivots, and recipient impact.
license: MIT
compatibility: Requires the claude-defender-xdr plugin and a Defender XDR sign-in (the first query opens the browser to sign in; `/defender-xdr:xdr-login` does it ahead of time), and access to Defender for Office 365 hunting tables.
---

# Defender XDR Messaging Investigation

Load and apply `defender-xdr-investigation` first; its hard guardrails, evidence funnel, ledger, stop conditions, and report contract control this investigation. This skill supplies the messaging branch.

## Messaging invariants

- Prefer `NetworkMessageId` for email and `TeamsMessageId` for Teams. Internet message IDs, subjects, URLs, and sender display names are weaker pivots.
- Separate original delivery, latest delivery state, and each post-delivery action/result.
- Separate URL presence, click, click disposition, click-through, and any endpoint or identity impact.
- Minimize message subjects, recipient addresses, and full URLs in queries and reports; include them only when they answer the question.
- Treat authentication, threat, campaign, rarity, and verdict fields as evidence requiring context rather than standalone conclusions.

## Messaging branch

1. **Resolve the message.** Map the supplied ID, sender, recipient, URL, hash, or alert evidence to stable message IDs inside the UTC interval. Continue when candidate message IDs are recorded and weaker matches are labeled.

2. **Reconstruct delivery.** Record sender identities/infrastructure, recipients or recipient counts, original and latest delivery fields, detections, authentication context, attachment hashes, and contained URLs. Continue when each message's delivery state is evidenced or missing fields are named.

3. **Verify remediation.** Retrieve post-delivery actions and inspect `ActionResult` for each affected message/recipient. Continue when current state is supported by the latest available event rather than inferred from action presence.

4. **Measure exposure and impact.** Aggregate delivered recipients first, then retrieve only relevant identities. Correlate clicks by message ID; inspect `ActionType` and `IsClickedThrough`. Use the identity or endpoint skill for post-click activity. Continue when delivered, clicked, click-through, and follow-on impact are separately counted or marked unknown.

5. **Scope the cluster.** Aggregate strong indicators such as attachment hashes, normalized URL/domain, sender infrastructure, or campaign ID before raw retrieval. Subject-only or display-name-only clusters remain weak. Continue when related message and recipient counts, first/last seen, and clustering basis are recorded.

6. **Challenge classification.** Compare historical legitimate traffic, forwarding/services that alter SPF/DKIM/DMARC, URL rewriting/redirects, shared mailbox/list behavior, and duplicated messages. Continue when the strongest benign explanation has evidence for or against it, or an explicit coverage gap.

7. **Return the messaging ledger.** Build an ordered UTC chain from receipt through delivery changes, clicks, alerts, and post-delivery results, preserving stable message and report IDs.

Use `xdr_get_schema` for uncertain columns, preview sources, or tenant drift. For the table map and bounded email, attachment, click, remediation, campaign, and Teams patterns, read only the relevant section of [references/query-patterns.md](references/query-patterns.md).
