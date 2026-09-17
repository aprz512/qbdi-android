mod call_tree_support;

use std::collections::BTreeMap;
use std::sync::Arc;

use call_tree_support::{BRANCH, CALL, FixtureStore, RETURN, Spec};
use qtrace_analysis::{
    CallTargetEvidence, CallTreeAnalyzer, CallTreeOptions, FrameState, IncompleteReason,
    IntervalKind,
};
use qtrace_provider::{
    CompletenessCause, CompletenessRange, Discontinuity, DiscontinuityCause, EventKind,
    EventPayload, OperationAbort, PcRelativeKind, Provenance, RegisterSlot, SignalHandlerPhase,
    Termination, TerminationKind, WorkDelta, WorkGuard,
};
use qtrace_store::RegisterAccess;

#[test]
fn direct_nested_calls_and_returns_form_a_tree() {
    let store = Arc::new(FixtureStore::new(vec![
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::immediate_call(11, 0x1100, 0x100),
        Spec::instruction(11, 0x1200, RETURN | BRANCH),
        Spec::instruction(11, 0x1104, RETURN | BRANCH),
    ]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();

    assert_eq!(tree.roots, vec![0]);
    assert_eq!(tree.nodes[0].children, vec![1]);
    assert_eq!(tree.nodes[0].target, Some(0x1100));
    assert_eq!(tree.nodes[1].target, Some(0x1200));
    assert_eq!(tree.nodes[0].state, FrameState::Complete);
    assert_eq!(tree.nodes[1].state, FrameState::Complete);
    assert_eq!(tree.nodes[0].target_evidence, CallTargetEvidence::Immediate);
}

#[test]
fn indirect_target_uses_next_pc_then_captured_register_then_lr() {
    let mut indirect = Spec::instruction(11, 0x1000, CALL | BRANCH);
    indirect.observations = vec![
        (RegisterSlot::X8, RegisterAccess::Read, 0x3000),
        (RegisterSlot::X30, RegisterAccess::Read, 0x1004),
    ];
    let store = Arc::new(FixtureStore::new(vec![
        indirect,
        Spec::instruction(11, 0x2000, RETURN | BRANCH),
    ]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();
    assert_eq!(tree.nodes[0].target, Some(0x2000));
    assert_eq!(tree.nodes[0].target_evidence, CallTargetEvidence::NextPc);

    let mut indirect = Spec::instruction(11, 0x1000, CALL | BRANCH);
    indirect.observations = vec![(RegisterSlot::X8, RegisterAccess::Read, 0x3000)];
    let store = Arc::new(FixtureStore::new(vec![indirect]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();
    assert_eq!(tree.nodes[0].target, Some(0x3000));
    assert_eq!(
        tree.nodes[0].target_evidence,
        CallTargetEvidence::CapturedRegister(RegisterSlot::X8)
    );
    assert_eq!(
        tree.nodes[0].state,
        FrameState::Incomplete(IncompleteReason::SourceEnd)
    );

    let mut indirect = Spec::instruction(11, 0x1000, CALL | BRANCH);
    indirect.observations = vec![(RegisterSlot::X30, RegisterAccess::Read, 0x4000)];
    let store = Arc::new(FixtureStore::new(vec![indirect]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();
    assert_eq!(tree.nodes[0].target, Some(0x4000));
    assert_eq!(
        tree.nodes[0].target_evidence,
        CallTargetEvidence::LinkRegister
    );
}

#[test]
fn a_gap_closes_open_frames_and_resets_parentage() {
    let gap = EventPayload::Discontinuity(Discontinuity {
        cause: DiscontinuityCause::Loss,
        evidence: CompletenessRange::captured_sequence_with_cause(
            2,
            2,
            Provenance::Damaged,
            CompletenessCause::Lost,
        )
        .unwrap(),
    });
    let store = Arc::new(FixtureStore::new(vec![
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::boundary(None, EventKind::Discontinuity, gap),
        Spec::immediate_call(11, 0x2000, 0x100),
    ]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();

    assert_eq!(
        tree.nodes[0].state,
        FrameState::Incomplete(IncompleteReason::Discontinuity)
    );
    assert_eq!(tree.nodes[1].parent, None);
}

#[test]
fn unmatched_return_signal_and_tail_call_are_explicit() {
    let mut tail = Spec::instruction(11, 0x1100, BRANCH);
    tail.pc_kind = PcRelativeKind::Instruction;
    tail.displacement = 0x100;
    let store = Arc::new(FixtureStore::new(vec![
        Spec::instruction(11, 0x800, RETURN | BRANCH),
        Spec::immediate_call(11, 0x1000, 0x100),
        tail,
        Spec::instruction(11, 0x1200, 0),
        Spec::signal(11, SignalHandlerPhase::Begin),
        Spec::signal(11, SignalHandlerPhase::Return),
    ]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();

    assert!(
        tree.intervals
            .iter()
            .any(|item| item.kind == IntervalKind::UnmatchedReturn)
    );
    assert!(
        tree.intervals
            .iter()
            .any(|item| item.kind == IntervalKind::SignalHandler)
    );
    assert!(tree.nodes.iter().any(|node| {
        node.state == FrameState::Incomplete(IncompleteReason::TailCall)
            && node.provenance == Provenance::Heuristic
    }));
    assert!(
        tree.nodes.iter().any(|node| {
            node.state == FrameState::Incomplete(IncompleteReason::SignalTransition)
        })
    );
}

#[test]
fn semantic_call_enriches_only_adjacent_instruction_context() {
    let store = Arc::new(FixtureStore::new(vec![
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::semantic(11, "jni", "CallObjectMethod"),
        Spec::instruction(11, 0x1100, RETURN | BRANCH),
        Spec::semantic(11, "libc", "malloc"),
    ]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();

    assert_eq!(tree.nodes[0].semantics[0].name, "CallObjectMethod");
    assert_eq!(tree.standalone_semantics.len(), 1);
    assert_eq!(tree.standalone_semantics[0].name, "malloc");
}

#[test]
fn unwind_to_an_ancestor_marks_only_abandoned_frames_heuristic() {
    let store = Arc::new(FixtureStore::new(vec![
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::immediate_call(11, 0x1100, 0x100),
        Spec::instruction(11, 0x1200, RETURN | BRANCH),
        Spec::instruction(11, 0x1004, 0),
    ]));
    let tree = CallTreeAnalyzer::new(store)
        .build(1, 11, &CallTreeOptions::default())
        .unwrap();

    assert_eq!(tree.nodes[0].state, FrameState::Complete);
    assert_eq!(
        tree.nodes[1].state,
        FrameState::Incomplete(IncompleteReason::Unwind)
    );
    assert_eq!(tree.nodes[1].provenance, Provenance::Heuristic);
    assert!(
        tree.intervals
            .iter()
            .any(|item| item.kind == IntervalKind::Unwind)
    );
}

struct Cancel;

impl WorkGuard for Cancel {
    fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
        Err(OperationAbort::Cancelled)
    }
}

struct DenyResident;

impl WorkGuard for DenyResident {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes != 0 {
            return Err(OperationAbort::budget_exceeded(
                qtrace_provider::BudgetDimension::ResidentBytes,
                0,
                delta.resident_bytes,
            ));
        }
        Ok(())
    }
}

#[test]
fn call_tree_build_is_cooperatively_cancellable() {
    let store = Arc::new(FixtureStore::new(vec![Spec::immediate_call(
        11, 0x1000, 0x100,
    )]));
    let error = CallTreeAnalyzer::new(store)
        .build_with_guard(1, 11, &CallTreeOptions::default(), &Cancel)
        .unwrap_err();
    assert_eq!(error.code(), "job.cancelled");
}

#[test]
fn call_tree_allocations_require_resident_budget() {
    let store = Arc::new(FixtureStore::new(vec![Spec::immediate_call(
        11, 0x1000, 0x100,
    )]));
    let error = CallTreeAnalyzer::new(store)
        .build_with_guard(1, 11, &CallTreeOptions::default(), &DenyResident)
        .unwrap_err();
    assert_eq!(error.code(), "analysis.budget_exceeded");
}

#[test]
fn trace_boundaries_termination_and_display_options_remain_explicit() {
    let termination = EventPayload::Termination(Termination {
        kind: TerminationKind::Stopped,
        reason: Some("operator".into()),
        return_value: None,
        ..Termination::default()
    });
    let store = Arc::new(FixtureStore::new(vec![
        Spec::instruction(11, 0x900, 0),
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::boundary(None, EventKind::Termination, termination),
    ]));
    let analyzer = CallTreeAnalyzer::new(store);
    let default_tree = analyzer.build(1, 11, &CallTreeOptions::default()).unwrap();
    assert!(default_tree.intervals.iter().any(|interval| {
        interval.kind == IntervalKind::TraceBoundary
            && interval.state == FrameState::Incomplete(IncompleteReason::SourceBegin)
    }));
    assert_eq!(
        default_tree.nodes[0].state,
        FrameState::Incomplete(IncompleteReason::Termination)
    );

    let options = CallTreeOptions {
        infer_tail_calls: true,
        display_names: BTreeMap::from([(0x1100, "named_target".into())]),
    };
    let named_tree = analyzer.build(1, 11, &options).unwrap();
    assert_eq!(named_tree.nodes[0].display, "named_target");
    assert_ne!(default_tree.identity, named_tree.identity);
}
