"""Attack Surface Discovery - Phase 1.2 (phases.md §1.2).

Discovers endpoints from three sources:
  * crawler (spider) - follows links found in HTML
  * OpenAPI/Swagger parser - parses API specs
  * browser (Playwright) - captures SPA/ajax traffic (Phase 1.4+, not shipped yet)

All sources produce the same `DiscoveredEndpoint` model so the Application Model
Builder (§1.4) can treat them uniformly.
"""