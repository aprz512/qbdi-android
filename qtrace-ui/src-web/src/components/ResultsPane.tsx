import { useEffect, useRef, useState } from "react";
import { useQtraceApi } from "../api/ApiContext";
import { normalizeAppError } from "../api/TauriQtraceApi";
import type { TimelinePageDto } from "../api/generated";

const PAGE_SIZE = 2_000;

interface ResultsPaneProps {
  workspaceId: string;
  projectionId: string;
  initialPage: TimelinePageDto;
  onJump(row: number): void;
}

export function ResultsPane({ workspaceId, projectionId, initialPage, onJump }: ResultsPaneProps) {
  const api = useQtraceApi();
  // The projection key resets this pane; subsequent timeline pages do not.
  const [page, setPage] = useState(initialPage);
  const [start, setStart] = useState(0);
  const [hit, setHit] = useState(-1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const request = useRef(0);
  const loading = useRef(false);
  useEffect(() => () => { request.current += 1; }, []);

  const jump = (index: number, targetPage = page) => {
    const row = targetPage.rows[index];
    if (row === undefined) return;
    setHit(index);
    onJump(row.source_row);
  };

  const changePage = async (direction: "previous" | "next", selectHit = false) => {
    if (loading.current || (direction === "previous" ? start === 0 : page.next_cursor === null)) return;
    loading.current = true;
    setBusy(true);
    setError(null);
    const token = ++request.current;
    try {
      let cursor = page.next_cursor;
      let nextStart = start + page.rows.length;
      if (direction === "previous") {
        const location = await api.locateTimelineOffset(workspaceId, projectionId, start - 1, PAGE_SIZE);
        if (token !== request.current) return;
        if (location === null) throw new Error("Previous results page is unavailable");
        cursor = location.cursor;
        nextStart = location.start;
      }
      const next = await api.queryTimeline(workspaceId, projectionId, cursor, PAGE_SIZE);
      if (token !== request.current) return;
      setPage(next);
      setStart(nextStart);
      setHit(-1);
      if (selectHit) jump(direction === "next" ? 0 : start - 1 - nextStart, next);
    } catch (failure) {
      if (token === request.current) setError(normalizeAppError(failure).detail);
    } finally {
      if (token === request.current) {
        loading.current = false;
        setBusy(false);
      }
    }
  };

  const previousHit = () => {
    if (hit > 0) jump(hit - 1);
    else void changePage("previous", true);
  };
  const nextHit = () => {
    if (hit < page.rows.length - 1) jump(hit + 1);
    else void changePage("next", true);
  };
  const pageNumber = Math.floor(start / PAGE_SIZE) + 1;
  return (
    <section aria-label="Search results" aria-busy={busy}>
      <h3>Results</h3>
      <p aria-live="polite">{page.exact_total ? `${page.total} results · exact total` : `At least ${page.total} results · indexing`}</p>
      <p>Page {pageNumber}{page.exact_total ? ` of ${Math.max(1, Math.ceil(page.total / PAGE_SIZE))}` : ""} · {page.rows.length === 0 ? "No rows on this page" : `Results ${start + 1}–${start + page.rows.length}`}</p>
      <nav aria-label="Results pages">
        <button disabled={busy || start === 0} onClick={() => void changePage("previous")}>Previous results page</button>
        <button disabled={busy || page.next_cursor === null} onClick={() => void changePage("next")}>Next results page</button>
      </nav>
      {error !== null && <p role="alert">{error}</p>}
      <button disabled={busy || (hit <= 0 && start === 0)} onClick={previousHit}>Previous hit</button>
      <button disabled={busy || (hit >= page.rows.length - 1 && page.next_cursor === null)} onClick={nextHit}>Next hit</button>
      <ol start={start + 1}>{page.rows.map((row, index) => <li key={`${row.key.artifact_sha256}:${row.key.timeline_id}:${row.key.record_ordinal}`}><button disabled={busy} aria-current={index === hit} onClick={() => jump(index)}>{row.kind} · {row.key.sequence ?? row.key.record_ordinal}</button></li>)}</ol>
    </section>
  );
}
