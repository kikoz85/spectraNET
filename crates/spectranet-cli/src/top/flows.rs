//! The Flow Inspector (`f`): every connection of the selected application with what kind of
//! traffic it carries and why, its handshake, and live waves of bandwidth and packets.
//!
//! Nothing here comes from the content of the communication: rates, packet counts, the
//! host name and the handshake fields sent in clear.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use spectranet_model::{Flow, Transport};

use super::state::{FlowSample, TopState};
use super::ui::{ACCENT, DIM, DOWN, UP, service};
use crate::flowtext::{certainty_word, kind_style, kind_word, packet_size, protocol, reason_text};
use crate::units::{rate, truncate_left};
use crate::view::{connection_rows, endpoint};

/// Unicode blocks for the waves, from empty to full.
const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let Some(app) = state.selected_app() else {
        return;
    };
    let rows = connection_rows(app);
    let selected = state.connection.min(rows.len().saturating_sub(1));
    // The list as tall as its rows (up to 40% of the screen), the detail takes the rest.
    let list_height = (rows.len() as u16 + 3).clamp(5, (area.height * 2 / 5).max(5));
    let [list, detail, waves] = Layout::vertical([
        Constraint::Length(list_height),
        Constraint::Min(8),
        Constraint::Length(8),
    ])
    .areas(area);

    // Connections, with their kind.
    let title = Line::from(vec![
        Span::styled(
            " Flow Inspector ",
            Style::new().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::styled(
            format!(
                " {} · pid {} · {} connections ",
                app.name,
                app.pid,
                app.flow_count()
            ),
            Style::new().fg(ACCENT).bold(),
        ),
    ]);
    let table_rows = rows.iter().map(|row| {
        let f = &row.flow;
        let (kind, color) = match &f.meta.class {
            Some(c) => {
                let (symbol, tag, (r, g, b)) = kind_style(c.kind);
                (format!("{symbol} {tag}"), Color::Rgb(r, g, b))
            }
            None => ("·".into(), Color::DarkGray),
        };
        let destination = match row.count {
            1 => endpoint(f),
            n => format!("* ({n} sockets)"),
        };
        let proto = match protocol(f) {
            p if p.is_empty() => service(f.transport, f.remote.port()).to_string(),
            p => p,
        };
        let pps = match (f.meta.rx_pps, f.meta.tx_pps) {
            (Some(r), Some(t)) => format!("{r}/{t}"),
            _ => String::new(),
        };
        Row::new([
            Cell::from(kind).style(Style::new().fg(color).bold()),
            Cell::from(truncate_left(&destination, 44)),
            Cell::from(proto).style(DIM),
            Cell::from(rate(f.rx_rate)).style(Style::new().fg(DOWN)),
            Cell::from(rate(f.tx_rate)).style(Style::new().fg(UP)),
            Cell::from(pps).style(DIM),
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
            "PKT/S ▼/▲",
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
                    " ↑↓ choose · d close · b block address · f / Esc back ",
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
        return;
    };
    let history = state
        .flow_history
        .get(&(
            row.owner.pid,
            row.flow.transport,
            row.flow.local,
            row.flow.remote,
        ))
        .map(|h| h.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    draw_detail(frame, detail, &row.flow);
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
