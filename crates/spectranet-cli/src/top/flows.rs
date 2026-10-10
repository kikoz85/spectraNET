//! The Flow Inspector (`f`): where the selected application connects — one row per host, all
//! its connections to that host together (a browser opens several per site, FTP one per file)
//! — with what kind of traffic it is and why, its handshake, and live waves of bandwidth and
//! packets.
//!
//! Nothing here comes from the content of the communication: rates, packet counts, the
//! host name and the handshake fields sent in clear.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use spectranet_intel::conversation;
use spectranet_model::{AppTraffic, Flow, Transport};

use super::state::{FlowSample, TopState};
use super::ui::{ACCENT, DIM, DOWN, UP, service};
use crate::flowtext::{certainty_word, kind_style, kind_word, packet_size, protocol, reason_text};
use crate::units::{bytes, rate, truncate_left};

/// Unicode blocks for the waves, from empty to full.
const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// One destination of the application: every connection to that host together.
pub(crate) struct HostRow {
    pub ip: std::net::IpAddr,
    /// (owning pid, connection)
    pub flows: Vec<(u32, Flow)>,
    pub combined: Flow,
    /// Bytes exchanged over the last minute.
    pub recent: u64,
}

/// The application's destinations, busiest over the last minute first (then by data
/// exchanged). Sockets without a remote end (listeners, local discovery) are left out.
pub(crate) fn host_rows(app: &AppTraffic, state: &TopState) -> Vec<HostRow> {
    let mut groups: Vec<(std::net::IpAddr, Vec<(u32, Flow)>)> = Vec::new();
    for p in &app.processes {
        for f in p.flows.iter().filter(|f| !f.remote.ip().is_unspecified()) {
            let ip = f.remote.ip();
            match groups.iter_mut().find(|g| g.0 == ip) {
                Some(g) => g.1.push((p.process.pid, f.clone())),
                None => groups.push((ip, vec![(p.process.pid, f.clone())])),
            }
        }
    }
    let mut rows: Vec<HostRow> = groups
        .into_iter()
        .filter_map(|(ip, flows)| {
            let combined = conversation::combine(flows.iter().map(|(_, f)| f))?;
            let recent = host_series(app, ip, state)
                .iter()
                .map(|s| s.rx + s.tx)
                .sum();
            Some(HostRow {
                ip,
                flows,
                combined,
                recent,
            })
        })
        .collect();
    rows.sort_by_key(|r| {
        std::cmp::Reverse(conversation::interest(
            r.recent,
            r.combined.rx_bytes + r.combined.tx_bytes,
        ))
    });
    rows
}

/// The last minute of the application's traffic with `ip`, all its processes together.
fn host_series(app: &AppTraffic, ip: std::net::IpAddr, state: &TopState) -> Vec<FlowSample> {
    let mut sum: Vec<FlowSample> = Vec::new();
    for p in &app.processes {
        let Some(h) = state.host_history.get(&(p.process.pid, ip)) else {
            continue;
        };
        // Align on the newest sample.
        if h.samples.len() > sum.len() {
            let missing = h.samples.len() - sum.len();
            sum.splice(0..0, std::iter::repeat_n(FlowSample::default(), missing));
        }
        let offset = sum.len() - h.samples.len();
        for (i, s) in h.samples.iter().enumerate() {
            let t = &mut sum[offset + i];
            t.rx += s.rx;
            t.tx += s.tx;
            t.rx_pps = match (t.rx_pps, s.rx_pps) {
                (None, None) => None,
                (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
            };
            t.tx_pps = match (t.tx_pps, s.tx_pps) {
                (None, None) => None,
                (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
            };
        }
    }
    sum
}

pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let Some(app) = state.selected_app() else {
        return;
    };
    let rows = host_rows(app, state);
    let selected = state.connection.min(rows.len().saturating_sub(1));
    // The list as tall as its rows (up to 40% of the screen), the detail takes the rest.
    let list_height = (rows.len() as u16 + 3).clamp(5, (area.height * 2 / 5).max(5));
    let [list, detail, waves] = Layout::vertical([
        Constraint::Length(list_height),
        Constraint::Min(8),
        Constraint::Length(8),
    ])
    .areas(area);

    // Destinations, with their kind.
    let title = Line::from(vec![
        Span::styled(
            " Flow Inspector ",
            Style::new().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::styled(
            format!(
                " {} · pid {} · {} destinations · {} connections ",
                app.name,
                app.pid,
                rows.len(),
                app.flow_count()
            ),
            Style::new().fg(ACCENT).bold(),
        ),
    ]);
    let table_rows = rows.iter().map(|row| {
        let f = &row.combined;
        let (kind, color) = match &f.meta.class {
            Some(c) => {
                let (symbol, tag, (r, g, b)) = kind_style(c.kind);
                (format!("{symbol} {tag}"), Color::Rgb(r, g, b))
            }
            None => ("·".into(), Color::DarkGray),
        };
        let host = f.remote_host.clone().unwrap_or_else(|| row.ip.to_string());
        let mut destination = format!(
            "{host}{}",
            conversation::ports_label(row.flows.iter().map(|(_, f)| f))
        );
        if row.flows.len() > 1 {
            destination.push_str(&format!(" ×{}", row.flows.len()));
        }
        let proto = match protocol(f) {
            p if p.is_empty() => service(f.transport, f.remote.port()).to_string(),
            p => p,
        };
        Row::new([
            Cell::from(kind).style(Style::new().fg(color).bold()),
            Cell::from(truncate_left(&destination, 44)),
            Cell::from(proto).style(DIM),
            Cell::from(rate(f.rx_rate)).style(Style::new().fg(DOWN)),
            Cell::from(rate(f.tx_rate)).style(Style::new().fg(UP)),
            Cell::from(bytes(row.recent)).style(DIM),
        ])
    });
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(13),
            Constraint::Min(24),
            Constraint::Length(16),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new([
            "KIND",
            "DESTINATION",
            "PROTOCOL",
            "▼ DOWN",
            "▲ UP",
            "LAST MIN",
        ])
        .style(Style::new().bold()),
    )
    .block(
        Block::new()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(ACCENT))
            .title(title)
            .title_bottom(
                Line::from(Span::styled(
                    " ↑↓ choose · d close · b block host · f / Esc back ",
                    DIM,
                ))
                .alignment(Alignment::Right),
            ),
    )
    .row_highlight_style(
        Style::new()
            .bg(Color::Rgb(20, 60, 80))
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");
    let mut table_state = TableState::default().with_selected(Some(selected));
    frame.render_stateful_widget(table, list, &mut table_state);

    let Some(row) = rows.get(selected) else {
        let empty = Paragraph::new(Line::from(Span::styled(
            " no connection with a destination right now",
            DIM,
        )));
        frame.render_widget(empty, detail);
        return;
    };
    let history = host_series(app, row.ip, state);
    draw_detail(frame, detail, &row.combined);
    draw_waves(frame, waves, &history);
}

fn label(text: &str) -> Span<'static> {
    Span::styled(format!(" {text:<14}"), DIM)
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, f: &Flow) {
    let mut lines = Vec::new();
    let target = match &f.remote_host {
        Some(h) => format!("{h} ({})", f.remote),
        None => f.remote.to_string(),
    };
    lines.push(Line::from(vec![
        label("DESTINATION"),
        Span::styled(target, Style::new().bold()),
        Span::styled(
            format!(
                "   {} {}",
                match f.transport {
                    Transport::Tcp => "tcp",
                    Transport::Udp => "udp",
                },
                service(f.transport, f.remote.port())
            ),
            DIM,
        ),
    ]));
    match &f.meta.tls {
        Some(tls) => {
            let mut parts = Vec::new();
            parts.push(if tls.quic {
                "QUIC (HTTP/3)".to_string()
            } else {
                tls.version.clone().unwrap_or_else(|| "TLS".into())
            });
            if let Some(c) = &tls.cipher {
                parts.push(c.clone());
            }
            if !tls.alpn.is_empty() {
                parts.push(format!("offers {}", tls.alpn.join(", ")));
            }
            lines.push(Line::from(vec![
                label("PROTOCOL"),
                Span::raw(parts.join(" · ")),
            ]));
            if let Some(ja4) = &tls.ja4 {
                lines.push(Line::from(vec![
                    label("CLIENT (JA4)"),
                    Span::styled(ja4.clone(), Style::new().fg(Color::Gray)),
                ]));
            }
            lines.push(Line::from(vec![
                label("STATUS"),
                Span::styled(
                    "🔒 encrypted — the content is unreadable along the way",
                    Style::new().fg(Color::Green),
                ),
            ]));
        }
        None => {
            let note = match (f.transport, f.remote.port()) {
                (Transport::Tcp, 80 | 21 | 23 | 110 | 143) => Span::styled(
                    "⚠ unencrypted protocol: readable by anyone along the way",
                    Style::new().fg(Color::Yellow),
                ),
                _ => Span::styled(
                    "handshake not seen (connection older than the capture, or capture unavailable)",
                    DIM,
                ),
            };
            lines.push(Line::from(vec![label("PROTOCOL"), note]));
        }
    }
    match &f.meta.class {
        Some(c) => {
            let (symbol, tag, (r, g, b)) = kind_style(c.kind);
            lines.push(Line::from(vec![
                label("CLASSIFIER"),
                Span::styled(
                    format!(" {symbol} {tag} "),
                    Style::new().fg(Color::Black).bg(Color::Rgb(r, g, b)).bold(),
                ),
                Span::styled(
                    format!(
                        "  probably {} — {}",
                        kind_word(c.kind),
                        certainty_word(c.certainty)
                    ),
                    Style::new().bold(),
                ),
            ]));
            for reason in &c.reasons {
                lines.push(Line::from(vec![
                    label(""),
                    Span::raw(format!("• {}", reason_text(reason))),
                ]));
            }
        }
        None => lines.push(Line::from(vec![
            label("CLASSIFIER"),
            Span::styled("not enough traffic yet to tell what it is", DIM),
        ])),
    }
    let sizes: Vec<String> = [
        ("▼", packet_size(f.rx_rate, f.meta.rx_pps)),
        ("▲", packet_size(f.tx_rate, f.meta.tx_pps)),
    ]
    .iter()
    .filter_map(|(d, s)| s.map(|s| format!("{d} {s} B")))
    .collect();
    if !sizes.is_empty() {
        lines.push(Line::from(vec![
            label("PACKET SIZE"),
            Span::raw(format!("{} on average", sizes.join("  "))),
        ]));
    }
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(DIM)
        .title(Span::styled(" STREAM ", Style::new().fg(ACCENT).bold()));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// A wave of block characters, scaled to its own peak, newest on the right.
pub fn wave(values: &[u64], width: usize) -> String {
    let shown = &values[values.len().saturating_sub(width)..];
    let peak = shown.iter().copied().max().unwrap_or(0).max(1);
    let mut out: String = std::iter::repeat_n(' ', width.saturating_sub(shown.len())).collect();
    out.extend(shown.iter().map(|v| {
        let level = ((*v as f64 / peak as f64) * 8.0).round() as usize;
        BLOCKS[level.min(8)]
    }));
    out
}

fn draw_waves(frame: &mut Frame<'_>, area: Rect, history: &[FlowSample]) {
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(DIM)
        .title(Span::styled(
            " BANDWIDTH & PACKETS · last minute ",
            Style::new().fg(ACCENT).bold(),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = usize::from(inner.width.saturating_sub(16));
    let series: [(&str, Color, Vec<u64>, String); 3] = {
        let rx: Vec<u64> = history.iter().map(|s| s.rx).collect();
        let tx: Vec<u64> = history.iter().map(|s| s.tx).collect();
        let pps: Vec<u64> = history
            .iter()
            .map(|s| u64::from(s.rx_pps.unwrap_or(0) + s.tx_pps.unwrap_or(0)))
            .collect();
        let peak = |v: &[u64]| v.iter().copied().max().unwrap_or(0);
        [
            ("▼ download", DOWN, rx.clone(), rate(peak(&rx))),
            ("▲ upload", UP, tx.clone(), rate(peak(&tx))),
            (
                "packets/s",
                Color::Magenta,
                pps.clone(),
                format!("{}/s", peak(&pps)),
            ),
        ]
    };
    let [a, b, c] = Layout::vertical([Constraint::Length(2); 3]).areas(inner);
    for ((name, color, values, peak), rect) in series.into_iter().zip([a, b, c]) {
        let line = Line::from(vec![
            Span::styled(format!(" {name:<13}"), Style::new().fg(color).bold()),
            Span::styled(wave(&values, width), Style::new().fg(color)),
        ]);
        let peak_line =
            Line::from(Span::styled(format!("peak {peak} "), DIM)).alignment(Alignment::Right);
        frame.render_widget(Paragraph::new(vec![line, peak_line]), rect);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waves_scale_to_their_peak_and_keep_the_newest() {
        assert_eq!(wave(&[0, 4, 8], 3), " ▄█");
        assert_eq!(wave(&[8, 8], 4), "  ██");
        assert_eq!(wave(&[1, 2, 3, 8], 2), "▃█");
        assert_eq!(wave(&[], 2), "  ");
        assert_eq!(wave(&[0, 0], 2), "  ");
    }
}
