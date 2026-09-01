use qtrace_provider::ProviderCapabilities;
use qtrace_provider::{
    CompletenessCause, DiscontinuityCause, EventKey, Provenance, RangeBounds, RangeDomain,
};
use qtrace_store::{CompletenessRow, NormalizedSourceFormat};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletenessStatus {
    Complete,
    Incomplete,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletenessSummary {
    pub retained_ranges: usize,
    pub incomplete_ranges: usize,
    pub status: CompletenessStatus,
    pub ranges: Vec<CompletenessRow>,
}

impl CompletenessSummary {
    pub(crate) fn new(
        ranges: Vec<CompletenessRow>,
        capabilities: &ProviderCapabilities,
        source_format: NormalizedSourceFormat,
        observed_sequence: Option<(u64, u64)>,
    ) -> Self {
        debug_assert!(
            ranges
                .windows(2)
                .all(|pair| { completeness_key(&pair[0]) <= completeness_key(&pair[1]) })
        );
        let retained_ranges = ranges
            .iter()
            .filter(|row| row.cause == CompletenessCause::Retained)
            .count();
        let incomplete_ranges = ranges.len() - retained_ranges;
        let status = if incomplete_ranges != 0 {
            CompletenessStatus::Incomplete
        } else if capabilities.loss_and_damage_ranges
            && match source_format {
                NormalizedSourceFormat::Qtrb => retained_covers_source_bytes(&ranges),
                NormalizedSourceFormat::Flight => observed_sequence
                    .is_some_and(|(first, last)| retained_covers_sequence(&ranges, first, last)),
                NormalizedSourceFormat::Other => false,
            }
        {
            CompletenessStatus::Complete
        } else {
            CompletenessStatus::Unknown
        };
        Self {
            retained_ranges,
            incomplete_ranges,
            status,
            ranges,
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self.status, CompletenessStatus::Complete)
    }
}

fn retained_covers_source_bytes(rows: &[CompletenessRow]) -> bool {
    let mut next = 0_u64;
    let mut saw_nonempty = false;
    for row in rows {
        let RangeBounds::HalfOpen {
            start,
            end_exclusive,
        } = row.bounds
        else {
            continue;
        };
        if row.domain != RangeDomain::SourceBytes || row.cause != CompletenessCause::Retained {
            continue;
        }
        if end_exclusive <= next {
            continue;
        }
        if start > next {
            return false;
        }
        saw_nonempty = true;
        next = end_exclusive;
    }
    saw_nonempty
}

fn retained_covers_sequence(rows: &[CompletenessRow], first: u64, last: u64) -> bool {
    let mut next = first;
    for row in rows {
        let RangeBounds::InclusiveSequence {
            first: range_first,
            last: range_last,
        } = row.bounds
        else {
            continue;
        };
        if row.domain != RangeDomain::CapturedSequence || row.cause != CompletenessCause::Retained {
            continue;
        }
        if range_last < next {
            continue;
        }
        if range_first > next {
            return false;
        }
        if range_last >= last {
            return true;
        }
        next = range_last.saturating_add(1);
    }
    false
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
