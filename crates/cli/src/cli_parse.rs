//! Parse repeatable global view filters without dropping ancestor occurrences.

use crate::args::{Cli, Cmd};
use clap::{CommandFactory, FromArgMatches};

/// Clap normally propagates a global argument by choosing the deepest
/// command's value. That is appropriate for scalar overrides, but loses
/// earlier `--contains` / `--not-contains` occurrences. Inherit these two
/// definitions explicitly before Clap builds its argument lookup tables, then
/// concatenate each command level's independent typed matches. Clap owns token,
/// value, subcommand, and conflict parsing; no raw-argv scanning is involved.
pub(crate) fn parse<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let command = Cli::command();
    let filters = command
        .get_arguments()
        .filter(|argument| matches!(argument.get_id().as_str(), "contains" | "not_contains"))
        .cloned()
        .map(|argument| argument.global(false))
        .collect::<Vec<_>>();
    let matches = keep_filter_occurrences(command, &filters).try_get_matches_from(arguments)?;
    let mut cli = Cli::from_arg_matches(&matches)?;
    cli.contains = collect_filter(&matches, "contains");
    cli.not_contains = collect_filter(&matches, "not_contains");
    if (!cli.contains.is_empty() || !cli.not_contains.is_empty())
        && matches!(cli.command, Cmd::Export { .. } | Cmd::Cache { .. })
    {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "--contains and --not-contains select report views; export and cache operations do not support these filters (export always preserves the complete graph)",
        ));
    }
    if cli.contains.is_empty()
        && matches!(
            cli.command,
            Cmd::Strings { regex: true, .. } | Cmd::Comments { regex: true, .. }
        )
    {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::MissingRequiredArgument,
            "--regex requires at least one --contains filter for strings/comments",
        ));
    }
    Ok(cli)
}

fn keep_filter_occurrences(mut command: clap::Command, filters: &[clap::Arg]) -> clap::Command {
    for filter in filters {
        let id = filter.get_id().as_str();
        if command.get_arguments().any(|argument| argument.get_id() == id) {
            command = command.mut_arg(id, |argument| argument.global(false));
        } else {
            command = command.arg(filter.clone());
        }
    }
    command.mut_subcommands(|child| keep_filter_occurrences(child, filters))
}

fn collect_filter(mut matches: &clap::ArgMatches, id: &str) -> Vec<String> {
    let mut values = Vec::new();
    loop {
        if let Some(found) = matches.try_get_many::<String>(id).ok().flatten() {
            values.extend(found.cloned());
        }
        let Some((_, child)) = matches.subcommand() else {
            break;
        };
        matches = child;
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_filters_do_not_corrupt_other_flag_lookup_tables() {
        for flag in ["--version", "-V"] {
            let error = parse(["bonsai-ninja", flag]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        }
        let cli = parse([
            "bonsai-ninja",
            "--no-color",
            "--parse-timeout",
            "12",
            "--memory-budget",
            "1024",
            "--contains",
            "root",
            "defs",
            ".",
            "--contains",
            "child",
            "--not-contains",
            "excluded",
        ])
        .unwrap();
        assert!(cli.no_color);
        assert_eq!(cli.parse_timeout_ms, Some(12));
        assert_eq!(cli.memory_budget_mb, Some(1024));
        assert_eq!(cli.contains, ["root", "child"]);
        assert_eq!(cli.not_contains, ["excluded"]);
    }

    #[test]
    fn repeatable_filters_accumulate_across_every_command_level() {
        let cli = parse([
            "bonsai-ninja",
            "--contains",
            "before",
            "security",
            ".",
            "--contains=middle",
            "--not-contains",
            "excluded-first",
            "sources",
            "--contains",
            "after",
            "--not-contains=excluded-last",
        ])
        .unwrap();
        assert_eq!(cli.contains, ["before", "middle", "after"]);
        assert_eq!(cli.not_contains, ["excluded-first", "excluded-last"]);
    }

    #[test]
    fn literal_inventory_filters_are_one_repeatable_global_argument() {
        for command in ["strings", "comments"] {
            let cli = parse([
                "bonsai-ninja",
                "--contains",
                "Alpha",
                command,
                ".",
                "--contains",
                "Token",
                "--contains=app.py",
                "--regex",
            ])
            .unwrap();
            assert_eq!(cli.contains, ["Alpha", "Token", "app.py"]);
        }
    }

    #[test]
    fn option_looking_values_are_not_reparsed_as_global_flags() {
        let cli = parse([
            "bonsai-ninja",
            "defs",
            ".",
            "--name=--contains",
            "--contains=--not-contains",
        ])
        .unwrap();
        assert_eq!(cli.contains, ["--not-contains"]);
        assert!(cli.not_contains.is_empty());
    }

    #[test]
    fn inventory_regex_requires_a_pattern_even_across_command_levels() {
        for command in ["strings", "comments"] {
            assert!(parse(["bonsai-ninja", command, ".", "--regex"]).is_err());
            assert!(parse(["bonsai-ninja", "--contains", "Alpha.*", command, ".", "--regex"]).is_ok());
        }
    }

    #[test]
    fn operations_reject_unsupported_view_filters_before_execution() {
        for arguments in [
            vec!["export", ".", "--contains", "absent"],
            vec!["--not-contains", "absent", "cache", "stats", "."],
            vec!["cache", "clear", ".", "--contains", "absent"],
            vec!["cache", "rebuild", ".", "--contains", "absent"],
        ] {
            assert!(parse(std::iter::once("bonsai-ninja").chain(arguments)).is_err());
        }
        assert!(parse(["bonsai-ninja", "index", ".", "--contains", "absent"]).is_ok());
    }
}
