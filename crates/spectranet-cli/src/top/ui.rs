//! Drawing `snet top`.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState,
};
use spectranet_model::{Transport, Verdict};

use super::keys::{Cmd, Column};
use super::state::{Confirm, Focus, Modal, SORT_ORDER, TopState, sort_label};
use super::tree;
use crate::cli::SortKey;
use crate::units::{bytes, rate, truncate, truncate_left};
use crate::view::{app_label, connection_rows, endpoint};

pub(super) const ACCENT: Color = Color::Cyan;
pub(super) const DOWN: Color = Color::Green;
pub(super) const UP: Color = Color::LightBlue;
pub(super) const DIM: Style = Style::new().fg(Color::DarkGray);

pub fn draw(frame: &mut Frame<'_>, state: &TopState) {
    let details = state.details && state.selected_app().is_some();
    let notice_lines = u16::from(!state.notices.is_empty());
    let [header, notice, graphs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(notice_lines),
        Constraint::Length(5),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_header(frame, header, state);
    if let Some(first) = state.notices.first() {
        let more = if state.notices.len() > 1 {
            format!(" (+{} more)", state.notices.len() - 1)
        } else {
            String::new()
        };
        frame.render_widget(
            Line::from(Span::styled(
                format!(" ⚠ {first}{more}"),
                Style::new().fg(Color::Yellow),
            )),
            notice,
        );
    }
    draw_graphs(frame, graphs, state);
    if state.flows && state.selected_app().is_some() {
        super::flows::draw(frame, body, state);
    } else if details {
        let [table, connections] =
            Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);
        draw_table(frame, table, state);
        draw_connections(frame, connections, state);
    } else {
        draw_table(frame, body, state);
    }
    draw_footer(frame, footer, state);
    match &state.modal {
        Some(Modal::Help) => draw_help(frame, state),
        Some(Modal::SortMenu { selected }) => draw_sort_menu(frame, state, *selected),
        Some(Modal::Setup(setup)) => draw_setup(frame, state, setup),
        Some(Modal::Confirm(confirm)) => draw_confirm(frame, confirm),
        None => {}
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let mut spans = vec![
        Span::styled(" spectra", Style::new().fg(ACCENT).bold()),
        Span::styled("NET", Style::new().fg(Color::White).bold()),
        Span::styled(format!("  ·  {}", state.source), DIM),
    ];
    if let Some(view) = &state.view {
        let processes: usize = view.apps.iter().map(|a| a.processes.len()).sum();
        let connections: usize = view.apps.iter().map(|a| a.flow_count()).sum();
        let flagged = view
            .apps
            .iter()
            .filter(|a| a.verdict >= Verdict::Warn)
            .count();
        spans.push(Span::styled(
            format!(
                "  ·  {} apps ({processes} processes)  ·  {connections} connections  ·  ",
                view.apps.len()
            ),
            DIM,
        ));
        spans.push(if flagged == 0 {
            Span::styled("no alerts", Style::new().fg(Color::Green))
        } else {
            Span::styled(
                format!("{flagged} flagged"),
                Style::new().fg(Color::Red).bold(),
            )
        });
    }
    if let Some(coverage) = state.coverage() {
        let style = if coverage < crate::view::COVERAGE_WARN {
            Style::new().fg(Color::Yellow).bold()
        } else {
            DIM
        };
        spans.push(Span::styled(
            format!("  ·  {:.0}% attributed", coverage * 100.0),
            style,
        ));
    }
    if state.tree {
        spans.push(Span::styled("  ·  tree", Style::new().fg(ACCENT)));
    }
    if state.frozen {
        spans.push(Span::styled(
            "  ❄ FROZEN",
            Style::new().fg(Color::Yellow).bold(),
        ));
    }
    frame.render_widget(Line::from(spans), area);
}

fn draw_graphs(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    graph(frame, left, "▼ download", &state.rx_history, DOWN);
    graph(frame, right, "▲ upload", &state.tx_history, UP);
}

fn graph(
    frame: &mut Frame<'_>,
    area: Rect,
    label: &str,
    history: &std::collections::VecDeque<u64>,
    color: Color,
) {
    let current = history.back().copied().unwrap_or(0);
    let peak = history.iter().copied().max().unwrap_or(0);
    let title = Line::from(vec![
        Span::styled(format!(" {label} "), Style::new().fg(color).bold()),
        Span::styled(format!("{} ", rate(current)), Style::new().bold()),
        Span::styled(format!("peak {} ", rate(peak)), DIM),
    ]);
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(DIM)
        .title(title);
    let width = usize::from(block.inner(area).width);
    let data: Vec<u64> = history
        .iter()
        .copied()
        .skip(history.len().saturating_sub(width))
        .collect();
    let sparkline = Sparkline::default()
        .block(block)
        .data(&data)
        .max(peak.max(1))
        .style(Style::new().fg(color));
    frame.render_widget(sparkline, area);
}

fn sort_of(column: Column) -> Option<SortKey> {
    match column {
        Column::Pid => Some(SortKey::Pid),
        Column::App => Some(SortKey::Name),
        Column::Down => Some(SortKey::Down),
        Column::Up => Some(SortKey::Up),
        Column::Cpu => Some(SortKey::Cpu),
        Column::Mem => Some(SortKey::Mem),
        Column::Total => Some(SortKey::Total),
        Column::Status => Some(SortKey::Alerts),
        Column::Conn | Column::User | Column::Destination => None,
    }
}

fn width(column: Column) -> Constraint {
    match column {
        Column::Pid => Constraint::Length(7),
        Column::App => Constraint::Min(22),
        Column::Down | Column::Up => Constraint::Length(11),
        Column::Cpu => Constraint::Length(6),
        Column::Mem => Constraint::Length(8),
        Column::Total => Constraint::Length(9),
        Column::Conn => Constraint::Length(5),
        Column::User => Constraint::Length(10),
        Column::Destination => Constraint::Min(16),
        Column::Status => Constraint::Length(8),
    }
}

fn header_cell(column: Column, current: SortKey) -> Cell<'static> {
    let title = column.title();
    if sort_of(column) == Some(current) {
        Cell::from(format!("{title}▾")).style(Style::new().fg(ACCENT).bold())
    } else {
        Cell::from(title)
    }
}

fn status_cell(verdict: Verdict, paused: bool) -> Cell<'static> {
    if paused {
        return Cell::from("⏸ paused").style(Style::new().fg(Color::Yellow));
    }
    match verdict {
        Verdict::Ok => Cell::from("ok").style(Style::new().fg(Color::Green)),
        Verdict::Warn => Cell::from("warn").style(Style::new().fg(Color::Yellow)),
        Verdict::Alert => {
            Cell::from("ALERT").style(Style::new().fg(Color::Red).add_modifier(Modifier::BOLD))
        }
    }
}

/// CPU with one decimal below 10 %, like top.
fn cpu_text(tenths: u32) -> String {
    if tenths < 100 {
        format!("{:.1}", tenths as f32 / 10.0)
    } else {
        format!("{}", tenths / 10)
    }
}

fn cell(column: Column, row: &tree::TreeRow, state: &TopState) -> Cell<'static> {
    let app = &row.app;
    let resources = app.processes.first().and_then(|p| p.resources.as_ref());
    let measured = app.processes.iter().any(|p| p.resources.is_some());
    match column {
        Column::Pid => Cell::from(app.pid.to_string()),
        Column::App => {
            let marker = if row.collapsed {
                format!("[+{}] ", row.descendants)
            } else {
                String::new()
            };
            Cell::from(format!("{}{}{}", tree::prefix(row), marker, app_label(app)))
                .style(Style::new().fg(ACCENT))
        }
        Column::Down => Cell::from(rate(app.rx_rate)).style(Style::new().fg(DOWN)),
        Column::Up => Cell::from(rate(app.tx_rate)).style(Style::new().fg(UP)),
        Column::Cpu if measured => {
            let style = if app.cpu_tenths >= 800 {
                Style::new().fg(Color::Red).bold()
            } else {
                Style::new()
            };
            Cell::from(cpu_text(app.cpu_tenths)).style(style)
        }
        Column::Mem if measured => Cell::from(bytes(app.memory)),
        Column::Cpu | Column::Mem => Cell::from("–").style(DIM),
        Column::Total => Cell::from(bytes(app.rx_bytes + app.tx_bytes)),
        Column::Conn => Cell::from(app.flow_count().to_string()),
        Column::User => Cell::from(truncate(
            resources.and_then(|r| r.user.as_deref()).unwrap_or("–"),
            10,
        ))
        .style(DIM),
        Column::Destination => Cell::from(truncate_left(
            &app.busiest_flow().map(endpoint).unwrap_or_default(),
            40,
        )),
        Column::Status => status_cell(app.verdict, state.paused.contains(&app.pid)),
    }
}

fn draw_table(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let columns = &state.settings.columns;
    let header =
        Row::new(columns.iter().map(|c| header_cell(*c, state.sort))).style(Style::new().bold());
    let title = format!(
        " {} · sorted by {} ",
        if state.tree {
            "process tree"
        } else {
            "applications"
        },
        sort_label(state.sort)
    );
    let focused = state.focus == Focus::Table;
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused && state.details {
            Style::new().fg(ACCENT)
        } else {
            DIM
        })
        .title(title);
    if state.view.is_none() {
        let message = if state.has_data() {
            "no data"
        } else {
            "waiting for the first sample…"
        };
        frame.render_widget(Paragraph::new(message).style(DIM).block(block), area);
        return;
    }
    if state.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("no matching applications")
                .style(DIM)
                .block(block),
            area,
        );
        return;
    }
    let rows = state
        .rows
        .iter()
        .map(|row| Row::new(columns.iter().map(|c| cell(*c, row, state))));
    let table = Table::new(rows, columns.iter().map(|c| width(*c)))
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::new()
                .bg(Color::Rgb(20, 60, 80))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut table_state = TableState::default().with_selected(Some(state.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

/// The service behind a port, as a word people know.
pub(super) fn service(transport: Transport, port: u16) -> &'static str {
    match (transport, port) {
        (Transport::Tcp, 443) => "https",
        (Transport::Udp, 443) => "quic",
        (Transport::Tcp, 80) => "http ⚠",
        (_, 53) => "dns",
        (Transport::Tcp, 853) => "dns/tls",
        (Transport::Tcp, 22) => "ssh",
        (Transport::Tcp, 993) => "imaps",
        (Transport::Tcp, 465 | 587) => "smtp",
        (Transport::Tcp, 21) => "ftp ⚠",
        (Transport::Tcp, 23) => "telnet ⚠",
        (Transport::Udp, 123) => "ntp",
        (Transport::Udp, 5353) => "mdns",
        (Transport::Tcp, 5223) => "apple push",
        (Transport::Tcp, 5228) => "google push",
        (Transport::Tcp, 3389) => "rdp",
        (_, 51820) => "wireguard",
        _ => "",
    }
}

fn draw_connections(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let Some(app) = state.selected_app() else {
        return;
    };
    let focused = state.focus == Focus::Connections;
    let mut title = vec![
        Span::styled(format!(" {} ", app.name), Style::new().fg(ACCENT).bold()),
        Span::styled(
            format!("· pid {} · {} connections ", app.pid, app.flow_count()),
            DIM,
        ),
    ];
    if app.processes.iter().any(|p| p.resources.is_some()) {
        title.push(Span::styled(
            format!(
                "· cpu {}% · mem {} ",
                cpu_text(app.cpu_tenths),
                bytes(app.memory)
            ),
            DIM,
        ));
    }
    if let Some(user) = app
        .processes
        .first()
        .and_then(|p| p.resources.as_ref())
        .and_then(|r| r.user.as_deref())
    {
        title.push(Span::styled(format!("· {user} "), DIM));
    }
    if let Some(path) = app.path.as_deref() {
        title.push(Span::styled(format!("· {} ", truncate_left(path, 50)), DIM));
    }
    let hint = if focused {
        " ↑↓ choose · d close it · Tab back "
    } else {
        " Tab: choose a connection "
    };
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { ACCENT } else { Color::DarkGray }))
        .title(Line::from(title))
        .title_bottom(Line::from(Span::styled(hint, DIM)).alignment(Alignment::Right));
    let grouped = app.processes.len() > 1;
    let rows = connection_rows(app).into_iter().map(|row| {
        let destination = match row.count {
            1 => endpoint(&row.flow),
            n => format!("* ({n} sockets)"),
        };
        let proto = match row.flow.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        };
        let note = row.flow.note.clone().unwrap_or_default();
        let owner = if grouped {
            format!("{} {}", row.owner.pid, row.owner.name)
        } else {
            String::new()
        };
        Row::new([
            Cell::from(proto),
            Cell::from(service(row.flow.transport, row.flow.remote.port())),
            Cell::from(truncate_left(&destination, 48)),
            Cell::from(rate(row.flow.rx_rate)).style(Style::new().fg(DOWN)),
            Cell::from(rate(row.flow.tx_rate)).style(Style::new().fg(UP)),
            Cell::from(bytes(row.flow.rx_bytes + row.flow.tx_bytes)),
            Cell::from(if note.is_empty() { owner } else { note }).style(DIM),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(12),
            Constraint::Min(24),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Length(30),
        ],
    )
    .header(
        Row::new(["", "SERVICE", "DESTINATION", "▼ DOWN", "▲ UP", "TOTAL", ""])
            .style(Style::new().bold()),
    )
    .block(block)
    .row_highlight_style(
        Style::new()
            .bg(Color::Rgb(20, 60, 80))
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(if focused { "▶ " } else { "  " });
    let mut table_state = TableState::default().with_selected(focused.then_some(state.connection));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn key_span(key: &str) -> Span<'static> {
    Span::styled(format!(" {key} "), Style::new().fg(Color::Black).bg(ACCENT))
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, state: &TopState) {
    let line = if let Some(buffer) = &state.editing {
        Line::from(vec![
            Span::styled(" search: ", Style::new().fg(ACCENT).bold()),
            Span::raw(buffer.clone()),
            Span::styled("█", Style::new().fg(ACCENT)),
            Span::styled(
                "   name (letters in order), hostname or address · enter apply · esc cancel",
                DIM,
            ),
        ])
    } else if let Some(error) = &state.error {
        Line::from(Span::styled(
            format!(" {error}"),
            Style::new().fg(Color::Red),
        ))
    } else if let Some((ok, message)) = &state.message {
        let (icon, color) = if *ok {
            ("✓", Color::Green)
        } else {
            ("✗", Color::Red)
        };
        Line::from(vec![
            Span::styled(format!(" {icon} {message}"), Style::new().fg(color)),
            Span::styled("   esc dismiss", DIM),
        ])
    } else {
        let keys = &state.settings.keys;
        let mut spans = Vec::new();
        for (cmd, what) in [
            (Cmd::Help, "help"),
            (Cmd::Setup, "setup"),
            (Cmd::Search, "search"),
            (Cmd::Tree, "tree"),
            (Cmd::SortMenu, "sort"),
            (Cmd::Inspect, "inspect"),
            (Cmd::Flows, "flows"),
            (Cmd::Kill, "kill"),
            (Cmd::Pause, "pause"),
            (Cmd::Quit, "quit"),
        ] {
            spans.push(key_span(keys.first(cmd)));
            spans.push(Span::styled(format!(" {what} "), DIM));
        }
        if !state.filter.is_empty() {
            spans.push(Span::styled(
                format!(" search: {} ", state.filter),
                Style::new().fg(Color::Yellow),
            ));
        }
        Line::from(spans)
    };
    frame.render_widget(line, area);
}

fn modal_block(title: &str) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(format!(" {title} "))
        .title_alignment(Alignment::Center)
}

fn draw_help(frame: &mut Frame<'_>, state: &TopState) {
    let keys = &state.settings.keys;
    let mut lines: Vec<Line<'_>> = Cmd::ALL
        .iter()
        .map(|cmd| {
            Line::from(vec![
                Span::styled(
                    format!("{:>18}  ", keys.keys(*cmd).join(" ")),
                    Style::new().fg(ACCENT).bold(),
                ),
                Span::raw(cmd.describe()),
            ])
        })
        .collect();
    for (k, what) in [
        (
            "Tab",
            "inspector: switch between the list and the connections",
        ),
        ("Esc", "close, then clear the search, then quit"),
        ("Ctrl-c", "quit"),
        (
            "",
            "keys can be changed in setup (F2) · press any key to close",
        ),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!("{k:>18}  "), Style::new().fg(ACCENT).bold()),
            Span::raw(what),
        ]));
    }
    let area = centered(frame.area(), 92, lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(modal_block("snet top · keys")),
        area,
    );
}

fn draw_sort_menu(frame: &mut Frame<'_>, state: &TopState, selected: usize) {
    let lines: Vec<Line<'_>> = SORT_ORDER
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let marker = if *key == state.sort { "● " } else { "  " };
            let style = if i == selected {
                Style::new().bg(Color::Rgb(20, 60, 80)).bold()
            } else {
                Style::new()
            };
            Line::from(Span::styled(
                format!(" {marker}{}", sort_label(*key)),
                style,
            ))
        })
        .collect();
    let area = centered(frame.area(), 40, lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(lines).block(modal_block("sort by")), area);
}

fn draw_setup(frame: &mut Frame<'_>, state: &TopState, setup: &super::state::Setup) {
    let tabs = Line::from(vec![
        Span::styled(
            " Columns ",
            if setup.tab == 0 {
                Style::new().fg(Color::Black).bg(ACCENT)
            } else {
                DIM
            },
        ),
        Span::raw("  "),
        Span::styled(
            " Keys ",
            if setup.tab == 1 {
                Style::new().fg(Color::Black).bg(ACCENT)
            } else {
                DIM
            },
        ),
        Span::styled("   Tab switch · Esc save and close", DIM),
    ]);
    let mut lines = vec![tabs, Line::raw("")];
    if setup.tab == 0 {
        for (i, column) in Column::ALL.iter().enumerate() {
            let on = state.settings.columns.contains(column);
            let style = if i == setup.selected {
                Style::new().bg(Color::Rgb(20, 60, 80)).bold()
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{}] {:<16}", if on { "x" } else { " " }, column.title()),
                    style,
                ),
                Span::styled(column.describe(), DIM),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            " Space or Enter shows / hides a column",
            DIM,
        )));
    } else {
        for (i, cmd) in Cmd::ALL.iter().enumerate() {
            let style = if i == setup.selected {
                Style::new().bg(Color::Rgb(20, 60, 80)).bold()
            } else {
                Style::new()
            };
            let keys = if setup.capturing == Some(*cmd) {
                "press a key…".to_string()
            } else {
                state.settings.keys.keys(*cmd).join(" ")
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {keys:<20}"), style.fg(ACCENT)),
                Span::styled(cmd.describe(), style),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            " Enter then a key: bind it · Backspace: back to the default",
            DIM,
        )));
    }
    let area = centered(frame.area(), 96, lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(lines).block(modal_block("setup")), area);
}

fn draw_confirm(frame: &mut Frame<'_>, confirm: &Confirm) {
    let (title, question, choices): (&str, String, Vec<(&str, &str)>) = match confirm {
        Confirm::Kill { name, .. } if cfg!(windows) => (
            "end process",
            format!("End {name} now? Unsaved work in it is lost."),
            vec![("y", "end it"), ("n", "cancel")],
        ),
        Confirm::Kill { name, .. } => (
            "end process",
            format!("End {name}?"),
            vec![
                ("t", "ask it to quit (SIGTERM)"),
                ("k", "force it (SIGKILL, unsaved work is lost)"),
                ("n", "cancel"),
            ],
        ),
        Confirm::Pause {
            name,
            resume: false,
            ..
        } => (
            "pause process",
            format!("Pause {name}? It stops using CPU and network until resumed (p again)."),
            vec![("y", "pause"), ("n", "cancel")],
        ),
        Confirm::Pause {
            name, resume: true, ..
        } => (
            "resume process",
            format!("Resume {name}?"),
            vec![("y", "resume"), ("n", "cancel")],
        ),
        Confirm::Drop { label, .. } => (
            "close connection",
            format!("Close the connection to {label}? The application may reconnect."),
            vec![("y", "close it"), ("n", "cancel")],
        ),
        Confirm::Block { label, .. } => (
            "block",
            format!("Block {label}? For how long:"),
            ["1", "2", "3", "4", "5"]
                .into_iter()
                .zip(crate::top::state::BLOCK_LENGTHS.iter().map(|(_, l)| *l))
                .chain([("n", "cancel")])
                .collect(),
        ),
    };
    let mut lines = vec![
        Line::raw(""),
        Line::from(Span::styled(format!(" {question}"), Style::new().bold())),
        Line::raw(""),
    ];
    let mut spans = vec![Span::raw(" ")];
    for (key, what) in choices {
        spans.push(key_span(key));
        spans.push(Span::raw(format!(" {what}   ")));
    }
    lines.push(Line::from(spans));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        " Protected system processes are always refused. Every action is logged by snetd.",
        DIM,
    )));
    // As wide as the longest line, so no choice is ever cut.
    let widest = lines.iter().map(Line::width).max().unwrap_or(40) as u16 + 4;
    let area = centered(frame.area(), widest.max(50), lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(lines).block(modal_block(title)), area);
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use spectranet_capture::mock::MockSource;

    use super::*;
    use crate::cli::{Cli, Command};

    fn state() -> TopState {
        let Command::List(list) = Cli::parse_from(["snet", "list"]).command else {
            unreachable!()
        };
        TopState::new(&list.view, "mock")
    }

    fn render(state: &TopState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn press(state: &mut TopState, code: KeyCode) {
        state.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn flow_inspector_shows_kinds_detail_and_waves() {
        let mut s = state();
        let mut source = MockSource::new(3);
        let mut classifier = spectranet_intel::classify::Classifier::new(
            spectranet_intel::classify::Domains::builtin(),
        );
        for _ in 0..8 {
            let mut snap = source.advance(Duration::from_secs(1));
            classifier.annotate(&mut snap);
            s.on_snapshot(snap);
        }
        // Select Chrome (it has a video connection) and open the inspector.
        s.filter = "chrome".into();
        s.on_snapshot({
            let mut snap = source.advance(Duration::from_secs(1));
            classifier.annotate(&mut snap);
            snap
        });
        press(&mut s, KeyCode::Char('f'));
        assert!(s.flows);
        let screen = render(&s, 150, 44);
        if std::env::var_os("SNET_SHOW").is_some() {
            println!("{screen}");
        }
        for text in [
            "Flow Inspector",
            "KIND",
            "VIDEO",
            "googlevideo.com",
            "STREAM",
            "CLASSIFIER",
            "known service of this kind",
            "BANDWIDTH & PACKETS",
        ] {
            assert!(screen.contains(text), "missing {text}\n{screen}");
        }
        press(&mut s, KeyCode::Esc);
        assert!(!s.flows && !s.details);
    }

    #[test]
    fn before_data_it_says_so() {
        let screen = render(&state(), 120, 30);
        assert!(screen.contains("waiting for the first sample"));
    }

    #[test]
    fn main_screen_shows_totals_graphs_and_apps() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        let screen = render(&s, 140, 30);
        for expected in [
            "spectraNET",
            "6 apps (7 processes)",
            "2 flagged",
            "▼ download",
            "▲ upload",
            "Google Chrome (2)",
            "svc_update",
            "ALERT",
            "APPLICATION",
            "▶ ",
        ] {
            assert!(screen.contains(expected), "missing {expected:?}\n{screen}");
        }
    }

    #[test]
    fn details_panel_lists_connections_of_selection() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        let name = s.selected_app().unwrap().name.clone();
        press(&mut s, KeyCode::Enter);
        let screen = render(&s, 140, 40);
        assert!(screen.contains(&format!(" {name} ")));
        assert!(screen.contains("DESTINATION"));
    }

    #[test]
    fn freeze_search_and_help_are_visible() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        press(&mut s, KeyCode::Char(' '));
        assert!(render(&s, 140, 30).contains("FROZEN"));
        press(&mut s, KeyCode::Char('/'));
        press(&mut s, KeyCode::Char('x'));
        assert!(render(&s, 140, 30).contains("search: x█"));
        press(&mut s, KeyCode::Esc);
        press(&mut s, KeyCode::F(1));
        let help = render(&s, 140, 40);
        assert!(help.contains("snet top · keys"));
        assert!(
            help.contains("F9 x") && help.contains("end the selected process"),
            "{help}"
        );
    }

    #[test]
    fn cpu_and_memory_columns_are_shown() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        let screen = render(&s, 160, 30);
        assert!(
            screen.contains("CPU%") && screen.contains("MEM"),
            "{screen}"
        );
        assert!(
            screen.contains(" MB") || screen.contains("MiB"),
            "memory values"
        );
    }

    #[test]
    fn sort_menu_setup_and_confirm_dialogs() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        press(&mut s, KeyCode::F(6));
        let menu = render(&s, 140, 40);
        assert!(
            menu.contains("sort by") && menu.contains("● bandwidth"),
            "{menu}"
        );
        press(&mut s, KeyCode::Esc);
        press(&mut s, KeyCode::F(2));
        let setup = render(&s, 140, 40);
        assert!(
            setup.contains("Columns") && setup.contains("[x] PID"),
            "{setup}"
        );
        press(&mut s, KeyCode::Tab);
        assert!(render(&s, 140, 40).contains("F9 x"));
        s.modal = Some(Modal::Confirm(Confirm::Pause {
            pid: 7,
            name: "curl (pid 7)".into(),
            resume: false,
        }));
        let confirm = render(&s, 140, 40);
        assert!(
            confirm.contains("Pause curl (pid 7)?") && confirm.contains("logged by snetd"),
            "{confirm}"
        );
    }

    #[test]
    fn inspector_shows_services_and_tree_shows_branches() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        press(&mut s, KeyCode::Enter);
        press(&mut s, KeyCode::Tab);
        let screen = render(&s, 160, 40);
        assert!(
            screen.contains("SERVICE") && screen.contains("d close it"),
            "{screen}"
        );
        press(&mut s, KeyCode::Esc);
        press(&mut s, KeyCode::Esc);
        press(&mut s, KeyCode::F(5));
        assert!(render(&s, 160, 40).contains("process tree"));
    }

    #[test]
    fn action_outcomes_appear_in_the_footer() {
        let mut s = state();
        s.message = Some((false, "pid 1 is protected".into()));
        assert!(render(&s, 140, 30).contains("✗ pid 1 is protected"));
        s.message = Some((true, "paused curl (pid 7)".into()));
        assert!(render(&s, 140, 30).contains("✓ paused curl"));
    }

    #[test]
    fn sorted_column_is_marked() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        press(&mut s, KeyCode::Char('s'));
        assert!(render(&s, 140, 30).contains("▼ DOWN▾"));
    }

    #[test]
    fn tiny_and_huge_terminals_do_not_panic() {
        let mut s = state();
        s.on_snapshot(MockSource::new(1).advance(Duration::from_secs(1)));
        press(&mut s, KeyCode::Enter);
        press(&mut s, KeyCode::Tab);
        press(&mut s, KeyCode::Char('?'));
        for (w, h) in [(1, 1), (10, 3), (40, 12), (80, 24), (400, 120)] {
            render(&s, w, h);
        }
        for modal in [
            Modal::SortMenu { selected: 3 },
            Modal::Setup(super::super::state::Setup {
                tab: 1,
                selected: 5,
                capturing: Some(Cmd::Kill),
            }),
            Modal::Confirm(Confirm::Kill {
                pid: 9,
                name: "x".repeat(300),
            }),
        ] {
            s.modal = Some(modal);
            for (w, h) in [(1, 1), (10, 3), (40, 12), (400, 120)] {
                render(&s, w, h);
            }
        }
    }

    #[test]
    fn notices_are_shown_under_the_header() {
        let mut s = state();
        s.notices = vec!["only /etc/hosts names are shown".into(), "second".into()];
        let screen = render(&s, 120, 30);
        assert!(screen.contains("⚠ only /etc/hosts names are shown (+1 more)"));
    }

    #[test]
    fn errors_are_shown_in_the_footer() {
        let mut s = state();
        s.on_error("snetd: connection closed".into());
        assert!(render(&s, 120, 30).contains("snetd: connection closed"));
    }
}
#[cfg(test)]
mod preview {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use spectranet_capture::mock::MockSource;

    #[test]
    #[ignore]
    fn print_screens() {
        let Command::List(list) = Cli::parse_from(["snet", "list"]).command else {
            unreachable!()
        };
        let mut s = TopState::new(&list.view, "snetd");
        let mut src = MockSource::new(1);
        for _ in 0..30 {
            s.on_snapshot(src.advance(std::time::Duration::from_secs(1)));
        }
        let show = |s: &TopState| {
            let mut t = Terminal::new(TestBackend::new(150, 40)).unwrap();
            t.draw(|f| draw(f, s)).unwrap();
            let b = t.backend().buffer().clone();
            for y in 0..b.area.height {
                println!(
                    "{}",
                    (0..b.area.width)
                        .map(|x| b[(x, y)].symbol().to_string())
                        .collect::<String>()
                );
            }
            println!("{}", "=".repeat(150));
        };
        show(&s);
        s.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        s.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        show(&s);
        s.modal = Some(Modal::Confirm(Confirm::Kill {
            pid: 4892,
            name: "Google Chrome (pid 4892)".into(),
        }));
        show(&s);
    }

    /// A terminal colour as CSS, in a dark theme like the README's screenshots.
    fn css(color: ratatui::style::Color, default: &str) -> String {
        use ratatui::style::Color;
        match color {
            Color::Reset => default.into(),
            Color::Black => "#0b1220".into(),
            Color::Red => "#f87171".into(),
            Color::Green => "#4ade80".into(),
            Color::Yellow => "#facc15".into(),
            Color::Blue => "#60a5fa".into(),
            Color::Magenta => "#c084fc".into(),
            Color::Cyan => "#22d3ee".into(),
            Color::Gray => "#a3b1c8".into(),
            Color::DarkGray => "#5b6b86".into(),
            Color::LightRed => "#fca5a5".into(),
            Color::LightGreen => "#86efac".into(),
            Color::LightYellow => "#fde68a".into(),
            Color::LightBlue => "#93c5fd".into(),
            Color::LightMagenta => "#e9d5ff".into(),
            Color::LightCyan => "#67e8f9".into(),
            Color::White => "#e8eef8".into(),
            Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
            Color::Indexed(i) => format!("hsl({} 60% 60%)", u16::from(i) * 7 % 360),
        }
    }

    /// One frame as an HTML page (for the README; turned into PNG by a browser).
    fn html(state: &TopState, width: u16, height: u16) -> String {
        use ratatui::style::Modifier;
        let mut t = Terminal::new(TestBackend::new(width, height)).unwrap();
        t.draw(|f| draw(f, state)).unwrap();
        let b = t.backend().buffer().clone();
        let mut out = String::from(
            "<!doctype html><meta charset=utf-8><style>body{margin:0;background:#0b1220}\
             pre{margin:0;padding:18px 22px;font:15px/1.25 'JetBrains Mono',Menlo,monospace;\
             color:#d6deeb;background:#0b1220;display:inline-block}</style><pre>",
        );
        for y in 0..b.area.height {
            let mut x = 0;
            while x < b.area.width {
                let cell = &b[(x, y)];
                let (fg, bg, m) = (cell.fg, cell.bg, cell.modifier);
                let mut text = String::new();
                while x < b.area.width {
                    let c = &b[(x, y)];
                    if (c.fg, c.bg, c.modifier) != (fg, bg, m) {
                        break;
                    }
                    for ch in c.symbol().chars() {
                        match ch {
                            '<' => text.push_str("&lt;"),
                            '>' => text.push_str("&gt;"),
                            '&' => text.push_str("&amp;"),
                            _ => text.push(ch),
                        }
                    }
                    x += 1;
                }
                let (mut fg, mut bg) = (css(fg, "#d6deeb"), css(bg, "transparent"));
                if m.contains(Modifier::REVERSED) {
                    std::mem::swap(&mut fg, &mut bg);
                    if fg == "transparent" {
                        fg = "#0b1220".into();
                    }
                }
                let weight = if m.contains(Modifier::BOLD) {
                    "bold"
                } else {
                    "normal"
                };
                let opacity = if m.contains(Modifier::DIM) {
                    "0.6"
                } else {
                    "1"
                };
                out.push_str(&format!(
                    "<span style=\"color:{fg};background:{bg};font-weight:{weight};opacity:{opacity}\">{text}</span>"
                ));
            }
            out.push('\n');
        }
        out.push_str("</pre>");
        out
    }

    /// `SNET_SHOTS=DIR cargo test -p spectranet-cli write_screens -- --ignored` writes the
    /// README's pictures of `snet top` as HTML pages.
    #[test]
    #[ignore]
    fn write_screens() {
        let Some(dir) = std::env::var_os("SNET_SHOTS").map(std::path::PathBuf::from) else {
            return;
        };
        std::fs::create_dir_all(&dir).unwrap();
        let Command::List(list) = Cli::parse_from(["snet", "list"]).command else {
            unreachable!()
        };
        let mut s = TopState::new(&list.view, "snetd");
        let mut src = MockSource::new(3);
        let mut classifier = spectranet_intel::classify::Classifier::new(
            spectranet_intel::classify::Domains::builtin(),
        );
        for _ in 0..160 {
            let mut snap = src.advance(std::time::Duration::from_secs(1));
            classifier.annotate(&mut snap);
            s.on_snapshot(snap);
        }
        std::fs::write(dir.join("snet-top.html"), html(&s, 150, 24)).unwrap();
        s.filter = "chrome".into();
        let mut snap = src.advance(std::time::Duration::from_secs(1));
        classifier.annotate(&mut snap);
        s.on_snapshot(snap);
        s.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
        std::fs::write(dir.join("snet-flows.html"), html(&s, 150, 42)).unwrap();
    }
}
