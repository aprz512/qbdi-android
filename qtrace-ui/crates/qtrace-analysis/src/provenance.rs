use qtrace_provider::{
    CompletenessCause, DiscontinuityCause, EventKey, Provenance, RangeBounds, RangeDomain,
};
use qtrace_store::CompletenessRow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletenessSummary {
    pub retained_ranges: usize,
    pub incomplete_ranges: usize,
    pub complete: bool,
    pub ranges: Vec<CompletenessRow>,
}

impl CompletenessSummary {
    pub(crate) fn new(rows: &[CompletenessRow]) -> Self {
        let mut ranges = rows.to_vec();
        ranges.sort_by_key(completeness_key);
        let retained_ranges = ranges
            .iter()
            .filter(|row| row.cause == CompletenessCause::Retained)
            .count();
        let incomplete_ranges = ranges.len() - retained_ranges;
        Self {
            retained_ranges,
            incomplete_ranges,
            complete: incomplete_ranges == 0,
            ranges,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscontinuityRow {
    pub source_row: usize,
    pub key: EventKey,
    pub provenance: Provenance,
    pub cause: DiscontinuityCause,
    pub evidence: CompletenessRow,
}

pub(crate) fn completeness_key(row: &CompletenessRow) -> (u8, u64, u64, u8, u8) {
    let domain = match row.domain {
        RangeDomain::CapturedSequence => 0,
        RangeDomain::SourceBytes => 1,
        RangeDomain::MemoryAddresses => 2,
    };
    let (start, end) = match row.bounds {
        RangeBounds::InclusiveSequence { first, last } => (first, last),
        RangeBounds::HalfOpen {
            start,
            end_exclusive,
        } => (start, end_exclusive),
    };
    (
        domain,
        start,
        end,
        provenance_tag(row.provenance),
        cause_tag(row.cause),
    )
}

fn provenance_tag(provenance: Provenance) -> u8 {
    match provenance {
        Provenance::Captured => 0,
        Provenance::Derived => 1,
        Provenance::Heuristic => 2,
        Provenance::Unknown => 3,
        Provenance::Damaged => 4,
    }
}

fn cause_tag(cause: CompletenessCause) -> u8 {
    match cause {
        CompletenessCause::Retained => 0,
        CompletenessCause::MissingTerminal => 1,
        CompletenessCause::Active => 2,
        CompletenessCause::Stale => 3,
        CompletenessCause::Rotating => 4,
        CompletenessCause::Unreliable => 5,
        CompletenessCause::Incomplete => 6,
        CompletenessCause::Lost => 7,
        CompletenessCause::Overwritten => 8,
        CompletenessCause::CoverageGap => 9,
        CompletenessCause::Checksum => 10,
        CompletenessCause::UnterminatedThread => 11,
        CompletenessCause::Truncation => 12,
        CompletenessCause::Unknown => 13,
    }
}
