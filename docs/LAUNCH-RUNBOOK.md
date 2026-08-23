# Launch day runbook — AgentScope

Everything below is prepared. This file is the order of operations.

## T-0: pre-flight (~10 min before posting)

- [ ] `gh run list -R sambai-dev/agentscope --limit 2` → both green
- [ ] Repo page loads logged-out (incognito) — README renders, badges green
- [ ] `docs/LAUNCH-REPLIES.md` open in a tab for the first hour
- [ ] Optional but strong: record 30s of the dashboard catching the simulated
      attack (serve + replay scenario.jsonl, screen-record the timeline +
      network map). Attach to the Reddit post; HN is text-first.

## Post order (same day)

1. **HN first**, morning US time = evening NZT.
   Title from `SHOW_HN_DRAFT.md`. Submit as a plain link post to
   github.com/sambai-dev/agentscope. Then immediately self-comment with the
   draft's body text (it's written to work as the author's first comment).
2. **r/rust ~2h later** — different framing than HN (the simulator story
   leads there, per REDDIT_POST.md). Reddit punishes identical cross-posts;
   the drafts are already differentiated.
3. **r/devops / r/programming next day** only if traction exists.

## First hour

- Answer every question within ~15 min for the first 90 minutes (that window
  decides HN rank). Use LAUNCH-REPLIES.md verbatim where it fits; trim to
  one paragraph when quoting.
- If "show me it catching something" comes up: reply with the two commands
  from the playbook's demo section.
- Never argue the root-bypass point beyond the playbook answer — it's a
  documented non-guarantee, not a flaw.

## Amplification triggers (watch cron fires daily 9am NZT)

| Signal | Action |
|---|---|
| Any repo crosses **5 stars** | Post portly/pulse/relay mention thread — "if you like this, I also built…" |
| agentscope crosses **10 stars** | r/devops cross-post + personal network ping |
| **25+ stars** | Write the follow-up post ("what HN taught me about agent security") while attention lasts |
| Issues appear | SLA: acknowledge < 24h (stated in coop's playbook; keep same bar here) |

## Known gaps to say out loud if asked

- GHCR pulse image still private (needs manual visibility flip)
- eBPF probes emit identity fields only today; argv/path extraction is roadmap
- No enforcement yet — observe-and-alert by design until LSM lands
