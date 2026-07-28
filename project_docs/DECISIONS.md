# Design Decisions

## Decision Log

### D1 — Work incrementally, never rewrite
- **Date**: 2026-07-27
- **Context**: Beginning project improvement
- **Decision**: Work one phase at a time, keep scanner working after each phase,
  never rewrite entire project, preserve backward compatibility
- **Rationale**: Minimizes risk, allows testing at each step, maintains
  user trust

### D2 — Single source of truth for progress
- **Date**: 2026-07-27
- **Context**: Need to track development across sessions
- **Decision**: `project_docs/development_progress.txt` is the mandatory SSOT
- **Rationale**: Enables session recovery after any interruption; prevents
  repeating completed work

### D3 — Fix evidence level comparison first
- **Date**: 2026-07-27
- **Context**: Phase 1 prioritization
- **Decision**: Fix enum-vs-string comparison as highest priority
- **Rationale**: This bug affects ALL findings' confidence scoring, making
  every vulnerability report potentially inaccurate

### D4 — Delete unused Classifier and Fingerprinter classes
- **Date**: 2026-07-27 (Phase 3)
- **Context**: Found unused Classifier and Fingerprinter classes
- **Decision**: Delete both files rather than keep as dead code
- **Rationale**: Dead code increases maintenance burden; if needed later,
  can be recreated from git history

### D5 — Shared session in Phase 2, not Phase 1
- **Date**: 2026-07-27
- **Context**: Every scanner creates its own session
- **Decision**: Introduce shared session in Phase 2 (Performance)
- **Rationale**: Phase 1 focuses on bugs; session sharing is an optimization
  that changes scanner constructors, better done in dedicated phase

### D6 — Scanner Registry pattern
- **Date**: 2026-07-27 (Phase 3)
- **Context**: main.py had 18 individual scanner imports
- **Decision**: Create scanners/registry.py with ALL/HOST/PAGE scanner lists
- **Rationale**: Adding a scanner = 1 import + 1 list entry; loose coupling
  between orchestration and detection modules

### D7 — Weighted-average confidence scoring
- **Date**: 2026-07-28 (Phase 4)
- **Context**: Confidence was calculated by summing bonuses, producing artifacts
- **Decision**: Switch to weighted average with base=50
- **Rationale**: More stable and predictable; evidence weight controls influence

### D8 — Multi-step verification for detection quality
- **Date**: 2026-07-28 (Phase 4)
- **Context**: All scanners reported findings on first signal, causing FPs
- **Decision**: Add confirmatory second payload for SQLi, XSS, LFI, SSRF
- **Rationale**: Dramatically reduces false positives at minimal performance cost

### D9 — Thread safety deferred to Phase 5
- **Date**: 2026-07-28
- **Context**: ScanResult.add_finding not thread-safe
- **Decision**: Fix in Phase 5 alongside other concurrency improvements
- **Rationale**: Requires coordinated changes to main.py run loop

## Architecture Principles

1. **Separation of concerns**: Core engine (data, decisions, reports) vs
   scanners (detection logic)
2. **Evidence-driven confidence**: Confidence calculated from evidence
   quality and quantity, not hardcoded
3. **Post-processing decision engine**: All scanners return raw findings,
   decision engine normalizes severity/CVSS/CWE
4. **Modular scanners**: Each vulnerability type in its own file, inheriting
   from BaseScanner
5. **Scanner Registry**: Loose coupling via registry list instead of direct imports
6. **Multi-step verification**: All major scanners confirm before reporting

## Future Considerations

- Move to async (asyncio + aiohttp) for better concurrency
- Plugin system for third-party scanners
- Configuration file (YAML/JSON) instead of hardcoded settings
- Real PDF generation (ReportLab or WeasyPrint)
- Proper logging framework (structlog or loguru)
- Docker containerization
- CI/CD pipeline with automated testing
