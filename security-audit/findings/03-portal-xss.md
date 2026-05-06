# 03 — Portal HTML XSS Audit

**Status:** Open
**Priority:** High
**Area:** XSS, Frontend Security

## Summary

The portal uses vanilla JS with `innerHTML` assignments. The `portal_welcome_message` server setting and other user-controlled data may be rendered without sanitization, creating stored XSS vectors.

## Key Questions

- [ ] Is `portal_welcome_message` rendered via `innerHTML` or `textContent`?
- [ ] What other fields are rendered without escaping (peer names, group names, etc.)?
- [ ] Can an admin inject script via settings that executes in portal user context?
- [ ] Are there DOM-based XSS vectors (URL parameters rendered into page)?

## Files to Review

- `app/static/portal.html`
- `app/static/admin.html`
- `app/static/captive.html`
- Any endpoint that returns HTML content

## Findings

<!-- Document results here -->

## Remediation

<!-- Document fixes here -->
