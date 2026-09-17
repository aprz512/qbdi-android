mod call_tree_support;

use std::sync::Arc;

use call_tree_support::{BRANCH, FixtureStore, RETURN, Spec};
use qtrace_analysis::{CallTreeAnalyzer, CallTreeOptions, FrameState, IncompleteReason};
use qtrace_provider::{
    CompletenessCause, CompletenessRange, Discontinuity, DiscontinuityCause, EventKind,
    EventPayload, Provenance,
};

#[test]
fn interleaved_threads_never_share_a_stack() {
    let store = Arc::new(FixtureStore::new(vec![
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::immediate_call(22, 0x2000, 0x100),
        Spec::instruction(11, 0x1100, RETURN | BRANCH),
        Spec::instruction(22, 0x2100, RETURN | BRANCH),
    ]));
    let trees = CallTreeAnalyzer::new(store)
        .build_all_threads(1, &CallTreeOptions::default())
        .unwrap();

    assert_eq!(trees[&11].nodes[0].tid, 11);
    assert_eq!(trees[&22].nodes[0].tid, 22);
    assert!(!trees[&11].nodes.iter().any(|node| node.tid == 22));
    assert_ne!(trees[&11].identity, trees[&22].identity);
}

#[test]
fn global_damage_closes_each_thread_without_cross_thread_parentage() {
    let gap = EventPayload::Discontinuity(Discontinuity {
        cause: DiscontinuityCause::Overwrite,
        evidence: CompletenessRange::captured_sequence_with_cause(
            3,
            3,
            Provenance::Damaged,
            CompletenessCause::Overwritten,
        )
        .unwrap(),
    });
    let store = Arc::new(FixtureStore::new(vec![
        Spec::immediate_call(11, 0x1000, 0x100),
        Spec::immediate_call(22, 0x2000, 0x100),
        Spec::boundary(None, EventKind::Discontinuity, gap),
        Spec::immediate_call(11, 0x3000, 0x100),
        Spec::immediate_call(22, 0x4000, 0x100),
    ]));
    let trees = CallTreeAnalyzer::new(store)
        .build_all_threads(1, &CallTreeOptions::default())
        .unwrap();

    for tree in trees.values() {
        assert_eq!(
            tree.nodes[0].state,
            FrameState::Incomplete(IncompleteReason::Discontinuity)
        );
        assert_eq!(tree.nodes[1].parent, None);
    }
}
