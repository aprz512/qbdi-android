//! Isolated service-open and bounded call-tree measurements. No timing threshold is a test.
use qtrace_service::{CallTreePageQuery, EventFilterDto, QtraceService};
use qtrace_store::AuthorizedPath;
use serde_json::json;
use std::{collections::HashSet, env, error::Error, path::PathBuf, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let argument = |name: &str| -> Result<PathBuf, Box<dyn Error>> {
        Ok(args
            .iter()
            .position(|value| value == name)
            .and_then(|at| args.get(at + 1))
            .ok_or_else(|| format!("missing {name}"))?
            .into())
    };
    let input = argument("--input")?.canonicalize()?;
    let cache = argument("--cache")?;
    let service = QtraceService::with_cache_root(cache);
    let started = Instant::now();
    let opened = if args.iter().any(|value| value == "--artifact") {
        service.open_artifact(AuthorizedPath::new(input))
    } else {
        service.open_session(AuthorizedPath::new(input))
    }
    .map_err(|error| format!("{}: {}", error.code, error.detail))?;
    let open_seconds = started.elapsed().as_secs_f64();
    let mut trees = Vec::new();
    if args.iter().any(|value| value == "--trees") {
        for artifact in &opened.artifacts {
            let projection = service
                .create_projection(
                    &opened.workspace.id,
                    artifact.index,
                    EventFilterDto {
                        kinds: vec!["instruction".into()],
                        ..Default::default()
                    },
                )
                .map_err(|error| format!("{}: {}", error.code, error.detail))?;
            let page = service
                .query_timeline(&opened.workspace.id, &projection.projection_id, None, 1)
                .map_err(|error| format!("{}: {}", error.code, error.detail))?;
            if let Some(row) = page.rows.first().filter(|row| row.key.tid.is_some()) {
                let started = Instant::now();
                let tree = service
                    .get_call_tree(
                        &opened.workspace.id,
                        artifact.index,
                        row.key.timeline_id.value(),
                        row.key.tid.unwrap(),
                        CallTreePageQuery::default(),
                    )
                    .map_err(|error| format!("{}: {}", error.code, error.detail))?;
                let first_seconds = started.elapsed().as_secs_f64();
                let started = Instant::now();
                let warm = service
                    .get_call_tree(
                        &opened.workspace.id,
                        artifact.index,
                        row.key.timeline_id.value(),
                        row.key.tid.unwrap(),
                        CallTreePageQuery::default(),
                    )
                    .map_err(|error| format!("{}: {}", error.code, error.detail))?;
                let warm_seconds = started.elapsed().as_secs_f64();
                assert_eq!(tree, warm);
                let mut visited = HashSet::new();
                let mut pending = vec![(None, 0, 1usize)];
                let mut page_seconds = Vec::new();
                let (mut max_nodes, mut max_bytes, mut max_depth) = (0, 0, 0);
                while let Some((parent, offset, depth)) = pending.pop() {
                    let started = Instant::now();
                    let page = service
                        .get_call_tree(
                            &opened.workspace.id,
                            artifact.index,
                            row.key.timeline_id.value(),
                            row.key.tid.unwrap(),
                            CallTreePageQuery {
                                parent,
                                offset,
                                expected_identity: Some(tree.identity.clone()),
                            },
                        )
                        .map_err(|error| format!("{}: {}", error.code, error.detail))?;
                    page_seconds.push(started.elapsed().as_secs_f64());
                    assert!(page.nodes.len() <= 100);
                    max_nodes = max_nodes.max(page.nodes.len());
                    max_bytes = max_bytes.max(serde_json::to_vec(&page)?.len());
                    let next = page.offset + page.nodes.len() as u32;
                    if next < page.total {
                        pending.push((parent, next, depth));
                    }
                    for node in page.nodes {
                        assert_eq!(node.parent, parent);
                        assert!(visited.insert(node.id), "call node appeared more than once");
                        max_depth = max_depth.max(depth);
                        service
                            .locate_timeline(
                                &opened.workspace.id,
                                &projection.projection_id,
                                node.source_row_start,
                                100,
                            )
                            .map_err(|error| error.detail)?
                            .ok_or("call node has no navigable instruction")?;
                        if node.child_count != 0 {
                            pending.push((Some(node.id), 0, depth + 1));
                        }
                    }
                }
                if let Some(at) = args.iter().position(|value| value == "--expected-nodes") {
                    assert_eq!(visited.len(), args[at + 1].parse::<usize>()?);
                }
                let stale = service
                    .get_call_tree(
                        &opened.workspace.id,
                        artifact.index,
                        row.key.timeline_id.value(),
                        row.key.tid.unwrap(),
                        CallTreePageQuery {
                            expected_identity: Some("stale".into()),
                            ..Default::default()
                        },
                    )
                    .unwrap_err();
                assert_eq!(stale.code, "call_tree.stale");
                trees.push(
                    json!({"artifact": artifact.index, "first_seconds": first_seconds,
                    "warm_seconds": warm_seconds, "bytes": serde_json::to_vec(&tree)?.len(),
                    "returned_nodes": tree.nodes.len(), "total_siblings": tree.total,
                    "traversed_nodes": visited.len(), "max_depth": max_depth,
                    "max_page_nodes": max_nodes, "max_page_bytes": max_bytes,
                    "page_seconds": page_seconds, "stale_identity_rejected": true}),
                );
            }
        }
    }
    let workspace = opened.workspace.id.clone();
    service
        .close_workspace(&workspace)
        .map_err(|error| error.detail)?;
    assert_eq!(
        service.workspace_summary(&workspace).unwrap_err().code,
        "workspace.stale"
    );
    println!(
        "{}",
        json!({"open_seconds": open_seconds, "opened": opened, "call_trees": trees})
    );
    Ok(())
}
