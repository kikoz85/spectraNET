//! Man page generation: `snet(1)` plus one page per visible subcommand (`snet-list(1)`, ...).
//!
//! clap_mangen renders the standard sections from the clap grammar; this module adds the
//! sections a Unix user expects (EXAMPLES, EXIT STATUS, ENVIRONMENT, SEE ALSO).

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Command, CommandFactory};
use clap_mangen::Man;

use crate::cli::Cli;
use crate::exit;

const MANUAL: &str = "spectraNET Manual";

/// Writes every page into `dir` and returns their paths.
pub fn generate(dir: &Path) -> io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut root = Cli::command().disable_help_subcommand(true);
    root.build();
    let source = format!("spectraNET {}", env!("CARGO_PKG_VERSION"));

    let subcommands: Vec<Command> = root
        .get_subcommands()
        .filter(|s| !s.is_hide_set())
        .cloned()
        .collect();
    let mut see_also: Vec<String> = subcommands.iter().map(page_name).collect();
    see_also.insert(0, "snet".into());

    let mut written = Vec::new();
    for cmd in std::iter::once(root.clone()).chain(subcommands) {
        let name = page_name(&cmd);
        let is_root = name == "snet";
        let man = Man::new(cmd.clone())
            .title(name.to_uppercase())
            .manual(MANUAL)
            .source(&source);

        let mut page = Vec::new();
        man.render_title(&mut page)?;
        man.render_name_section(&mut page)?;
        man.render_synopsis_section(&mut page)?;
        man.render_description_section(&mut page)?;
        man.render_options_section(&mut page)?;
        if is_root {
            man.render_subcommands_section(&mut page)?;
        }
        render_examples(&mut page, &cmd)?;
        render_exit_status(&mut page)?;
        if is_root {
            render_environment(&mut page)?;
        }
        let others: Vec<&str> = see_also
            .iter()
            .map(String::as_str)
            .filter(|p| *p != name)
            .collect();
        render_see_also(&mut page, &others)?;
        man.render_version_section(&mut page)?;

        let path = dir.join(format!("{name}.1"));
        std::fs::write(&path, page)?;
        written.push(path);
    }
    Ok(written)
}

/// `snet` for the root command, `snet-<sub>` for subcommands.
fn page_name(cmd: &Command) -> String {
    cmd.get_display_name().unwrap_or(cmd.get_name()).to_string()
}

/// Turns the "Examples:" block of the long help into a roff EXAMPLES section.
/// Lines look like `  snet list --json` or `  snet list    Description`.
fn render_examples(w: &mut dyn Write, cmd: &Command) -> io::Result<()> {
    let Some(help) = cmd.get_after_long_help() else {
        return Ok(());
    };
    let help = help.to_string();
    let lines: Vec<&str> = help
        .lines()
        .skip_while(|l| !l.starts_with("Examples:"))
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return Ok(());
    }
    writeln!(w, ".SH EXAMPLES")?;
    for line in lines {
        let (example, description) = match line.find("  ") {
            Some(i) => (line[..i].trim(), line[i..].trim()),
            None => (line, ""),
        };
        writeln!(w, ".TP\n.B {}", escape(example))?;
        if !description.is_empty() {
            writeln!(w, "{}", escape(description))?;
        }
    }
    Ok(())
}

fn render_exit_status(w: &mut dyn Write) -> io::Result<()> {
    writeln!(w, ".SH \"EXIT STATUS\"")?;
    for (code, meaning) in exit::DOCUMENTED {
        writeln!(w, ".TP\n.B {code}\n{}", escape(meaning))?;
    }
    Ok(())
}

fn render_environment(w: &mut dyn Write) -> io::Result<()> {
    writeln!(w, ".SH ENVIRONMENT")?;
    writeln!(
        w,
        ".TP\n.B NO_COLOR\nWhen set to a non-empty value, disables colored output unless \\fB\\-\\-color always\\fR is given."
    )?;
    writeln!(
        w,
        ".TP\n.B CLICOLOR_FORCE\nWhen set to a non-empty value, forces colored output even when not writing to a terminal."
    )
}

fn render_see_also(w: &mut dyn Write, pages: &[&str]) -> io::Result<()> {
    writeln!(w, ".SH \"SEE ALSO\"")?;
    let mut refs: Vec<String> = pages
        .iter()
        .map(|p| format!(".BR {} (1)", escape(p)))
        .collect();
    refs.push(".BR snetd (8)".into());
    writeln!(w, "{}", refs.join(",\n"))
}

/// Escapes text for roff: backslashes, hyphens, and leading control characters.
fn escape(text: &str) -> String {
    let escaped = text.replace('\\', "\\e").replace('-', "\\-");
    if escaped.starts_with('.') || escaped.starts_with('\'') {
        format!("\\&{escaped}")
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_one_page_per_visible_command() {
        let dir = std::env::temp_dir().join(format!("snet-man-{}", std::process::id()));
        let pages = generate(&dir).unwrap();
        let names: Vec<_> = pages
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "snet.1",
                "snet-list.1",
                "snet-watch.1",
                "snet-top.1",
                "snet-status.1",
                "snet-history.1",
                "snet-record.1",
                "snet-analyze.1",
                "snet-kill.1",
                "snet-pause.1",
                "snet-resume.1",
                "snet-drop.1",
                "snet-stream.1",
                "snet-inspect.1",
                "snet-block.1",
                "snet-unblock.1",
                "snet-blocks.1",
                "snet-audit.1",
                "snet-alerts.1",
                "snet-check.1",
            ]
        );

        let root = std::fs::read_to_string(dir.join("snet.1")).unwrap();
        for section in [
            ".TH SNET 1",
            ".SH SYNOPSIS",
            ".SH EXAMPLES",
            ".SH \"EXIT STATUS\"",
            ".SH ENVIRONMENT",
            ".BR snet\\-list (1)",
            ".BR snetd (8)",
        ] {
            assert!(root.contains(section), "snet.1 is missing {section}");
        }
        assert!(
            !root.contains("generate"),
            "hidden command leaked into the man page"
        );

        let list = std::fs::read_to_string(dir.join("snet-list.1")).unwrap();
        assert!(list.contains("\\-\\-connections"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn escapes_roff_specials() {
        assert_eq!(escape("snet list --json"), "snet list \\-\\-json");
        assert_eq!(escape(".hidden"), "\\&.hidden");
        assert_eq!(escape("a\\b"), "a\\eb");
    }
}
