//! The process tree (F5): every network process under its parent, like htop's tree view.
//!
//! Only processes with network activity are listed; one whose parent has none starts a
//! branch of its own. A collapsed branch shows its whole subtree's traffic, CPU and memory
//! on the parent row.

use std::collections::{HashMap, HashSet};

use spectranet_model::AppTraffic;

/// One row of the tree.
#[derive(Debug, Clone, PartialEq)]
pub struct TreeRow {
    /// The process (or, for a collapsed branch, the parent with its subtree summed in).
    pub app: AppTraffic,
    pub depth: usize,
    /// Number of descendants (0 for a leaf).
    pub descendants: usize,
    pub collapsed: bool,
    /// Whether this is the last child of its parent (for drawing └ instead of ├).
    pub last: bool,
}

/// Orders one-process rows (`apps`, already sorted) as a tree; siblings keep that order.
pub fn build(apps: &[AppTraffic], collapsed: &HashSet<u32>) -> Vec<TreeRow> {
    let index: HashMap<u32, usize> = apps.iter().enumerate().map(|(i, a)| (a.pid, i)).collect();
    let parent_of = |a: &AppTraffic| {
        a.processes
            .first()
            .and_then(|p| p.resources.as_ref())
            .and_then(|r| r.ppid)
            .filter(|pp| *pp != a.pid && index.contains_key(pp))
    };
    let mut children: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();
    for (i, a) in apps.iter().enumerate() {
        match parent_of(a) {
            Some(pp) => children.entry(pp).or_default().push(i),
            None => roots.push(i),
        }
    }
    // A cycle (pid reuse can create one) would leave processes unreachable: start them as
    // roots so nothing ever disappears.
    let mut out = Vec::with_capacity(apps.len());
    let mut visited = HashSet::new();
    for (k, &root) in roots.iter().enumerate() {
        walk(
            apps,
            &children,
            collapsed,
            root,
            0,
            k + 1 == roots.len(),
            &mut visited,
            &mut out,
        );
    }
    for i in 0..apps.len() {
        if !visited.contains(&i) {
            walk(
                apps,
                &children,
                collapsed,
                i,
                0,
                true,
                &mut visited,
                &mut out,
            );
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn walk(
    apps: &[AppTraffic],
    children: &HashMap<u32, Vec<usize>>,
    collapsed: &HashSet<u32>,
    i: usize,
    depth: usize,
    last: bool,
    visited: &mut HashSet<usize>,
    out: &mut Vec<TreeRow>,
) {
    if !visited.insert(i) {
        return;
    }
    let app = &apps[i];
    let kids = children.get(&app.pid).cloned().unwrap_or_default();
    let descendants = count(apps, children, i, &mut HashSet::new());
    let is_collapsed = collapsed.contains(&app.pid) && !kids.is_empty();
    if is_collapsed {
        let mut members = Vec::new();
        gather(apps, children, i, &mut HashSet::new(), &mut members);
        let processes = members
            .iter()
            .flat_map(|m| apps[*m].processes.clone())
            .collect();
        let mut summed = AppTraffic::new(processes);
        // Keep the parent's identity on the row.
        summed.pid = app.pid;
        summed.name = app.name.clone();
        summed.path = app.path.clone();
        out.push(TreeRow {
            app: summed,
            depth,
            descendants,
            collapsed: true,
            last,
        });
        for m in members {
            visited.insert(m);
        }
        return;
    }
    out.push(TreeRow {
        app: app.clone(),
        depth,
        descendants,
        collapsed: false,
        last,
    });
    for (k, &child) in kids.iter().enumerate() {
        walk(
            apps,
            children,
            collapsed,
            child,
            depth + 1,
            k + 1 == kids.len(),
            visited,
            out,
        );
    }
}

fn count(
    apps: &[AppTraffic],
    children: &HashMap<u32, Vec<usize>>,
    i: usize,
    seen: &mut HashSet<usize>,
) -> usize {
    if !seen.insert(i) {
        return 0;
    }
    children.get(&apps[i].pid).map_or(0, |kids| {
        kids.iter()
            .map(|&k| 1 + count(apps, children, k, seen))
            .sum()
    })
}

fn gather(
    apps: &[AppTraffic],
    children: &HashMap<u32, Vec<usize>>,
    i: usize,
    seen: &mut HashSet<usize>,
    out: &mut Vec<usize>,
) {
    if !seen.insert(i) {
        return;
    }
    out.push(i);
    for &k in children.get(&apps[i].pid).map_or(&[][..], |v| v.as_slice()) {
        gather(apps, children, k, seen, out);
    }
}

/// Tree branch drawing for a row: `├─ `, `└─ `, indented by depth.
pub fn prefix(row: &TreeRow) -> String {
    if row.depth == 0 {
        return String::new();
    }
    format!(
        "{}{}",
        "  ".repeat(row.depth - 1),
        if row.last { "└─ " } else { "├─ " }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::{Flow, Process, ProcessTraffic, Resources, Transport, Verdict};

    fn proc(pid: u32, ppid: u32, rx: u64) -> AppTraffic {
        let flow = Flow {
            meta: Default::default(),
            transport: Transport::Tcp,
            local: "10.0.0.2:5000".parse().unwrap(),
            remote: "1.2.3.4:443".parse().unwrap(),
            remote_host: None,
            rx_rate: rx,
            tx_rate: 0,
            rx_bytes: rx,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
        };
        let mut p = ProcessTraffic::new(
            Process {
                pid,
                name: format!("p{pid}"),
                path: None,
                app: None,
            },
            vec![flow],
        );
        p.resources = Some(Resources {
            ppid: Some(ppid),
            cpu_tenths: 10,
            memory: 1000,
            user: None,
        });
        AppTraffic::new(vec![p])
    }

    #[test]
    fn children_follow_their_parent() {
        // nginx master 10 with workers 11, 12; worker 12 has a helper 13; 20 is unrelated.
        let apps = vec![
            proc(12, 10, 50),
            proc(20, 1, 40),
            proc(10, 1, 5),
            proc(11, 10, 30),
            proc(13, 12, 1),
        ];
        let rows = build(&apps, &HashSet::new());
        let order: Vec<(u32, usize)> = rows.iter().map(|r| (r.app.pid, r.depth)).collect();
        assert_eq!(order, [(20, 0), (10, 0), (12, 1), (13, 2), (11, 1)]);
        assert_eq!(rows[1].descendants, 3);
        assert!(rows.last().unwrap().last);
        assert_eq!(prefix(&rows[3]), "  └─ ");
    }

    #[test]
    fn collapsed_branches_sum_into_the_parent() {
        let apps = vec![proc(10, 1, 5), proc(11, 10, 30), proc(12, 10, 50)];
        let rows = build(&apps, &HashSet::from([10]));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].collapsed);
        assert_eq!(rows[0].app.pid, 10);
        assert_eq!(rows[0].app.rx_rate, 85);
        assert_eq!(rows[0].app.cpu_tenths, 30);
        assert_eq!(rows[0].descendants, 2);
    }

    #[test]
    fn cycles_and_orphans_never_lose_a_process() {
        // 30 and 31 claim each other as parent (PID reuse can do that).
        let apps = vec![proc(30, 31, 1), proc(31, 30, 1), proc(40, 999, 1)];
        let rows = build(&apps, &HashSet::new());
        let mut pids: Vec<u32> = rows.iter().map(|r| r.app.pid).collect();
        pids.sort();
        assert_eq!(pids, [30, 31, 40]);
    }
}
