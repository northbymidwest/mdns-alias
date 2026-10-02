//! The command line.

use crate::wire::Name;

const USAGE: &str = "usage: mdns-alias [--interface <name>]... [--require-sandbox] <name.local>...";

#[derive(Debug, PartialEq)]
pub struct Cli {
    /// `--interface` names; empty means the default set.
    pub interfaces: Vec<String>,
    /// The aliases, each a full `.local` name, deduplicated ignoring case,
    /// in the order given.
    pub aliases: Vec<Name>,
    /// Exit rather than run with any sandbox layer missing.
    pub require_sandbox: bool,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let mut interfaces = Vec::new();
    let mut names = Vec::new();
    let mut require_sandbox = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if let Some(option) = removed(&arg) {
            return Err(format!(
                "{option} was removed: aliases are published as address records, \
                 and each is a full name ending in .local\n{USAGE}"
            ));
        }
        match arg.as_str() {
            "--interface" => interfaces.push(args.next().ok_or(USAGE)?),
            "--require-sandbox" => require_sandbox = true,
            option if option.starts_with('-') => return Err(USAGE.into()),
            _ => names.push(arg),
        }
    }
    if names.is_empty() {
        return Err(USAGE.into());
    }
    let mut aliases: Vec<Name> = Vec::new();
    for text in &names {
        let alias = alias(text)?;
        if !aliases.contains(&alias) {
            aliases.push(alias);
        }
    }
    Ok(Cli {
        interfaces,
        aliases,
        require_sandbox,
    })
}

/// The removed option `arg` is, alone or as `--option=value`.
fn removed(arg: &str) -> Option<&'static str> {
    ["--cname", "--host", "--target"]
        .into_iter()
        .find(|option| {
            arg.strip_prefix(option)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('='))
        })
}

/// `text` as an alias: a valid name ending in `.local` (a trailing dot, as
/// in DNS, is allowed), every label of it a valid host name label.
/// Several labels before `.local` are fine (`api.app.local`). A name
/// without `.local` gets `<name>.local` suggested only when that would be
/// a sensible alias: a single valid label, other than `local` itself.
fn alias(text: &str) -> Result<Name, String> {
    let name = Name::parse(text).map_err(|e| format!("invalid name {text:?}: {e}"))?;
    if let Some(label) = bad_label(&name) {
        return Err(format!(
            "invalid name {:?}: label {label:?} {LABEL_RULE}",
            name.to_string()
        ));
    }
    if !name.is_local() {
        let bare = text.strip_suffix('.').unwrap_or(text);
        if name.labels().count() == 1 && !bare.eq_ignore_ascii_case("local") {
            return Err(format!("{text:?} is not a .local name; write {bare}.local"));
        }
        return Err(format!(
            "{text:?} is not a .local name; an alias must end in .local"
        ));
    }
    Ok(name)
}

/// This machine's own `.local` name, made from its host name (the
/// kernel's, as `uname` gives it): the first label, plus `.local`. `None`
/// if that is not a valid alias.
fn own_name(host_name: &str) -> Option<Name> {
    let first = host_name.trim().split('.').next()?;
    let name = Name::parse(&format!("{first}.local")).ok()?;
    bad_label(&name).is_none().then_some(name)
}

/// Refuses an alias that is this machine's own `.local` name, made from
/// `host_name` (see `own_name`): the host's responder already publishes
/// it, and our goodbyes on shutdown would withdraw it from caches. Without
/// a host name, or with one that makes no valid name, nothing is checked.
pub fn check_own_name(aliases: &[Name], host_name: Option<&str>) -> Result<(), String> {
    let Some(own) = host_name.and_then(own_name) else {
        return Ok(());
    };
    match aliases.iter().find(|alias| **alias == own) {
        Some(alias) => Err(format!(
            "{alias} is this machine's own name ({own}); its responder already publishes it"
        )),
        None => Ok(()),
    }
}

/// The first label of `name` that is not a valid host name label: ASCII
/// letters, digits and hyphens only, not starting or ending with a hyphen
/// (RFC 1123 section 2.1). This is the command line's rule for what to
/// publish; the wire code still accepts any bytes from the network.
fn bad_label(name: &Name) -> Option<String> {
    name.labels()
        .find(|label| {
            !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
                || label.starts_with(b"-")
                || label.ends_with(b"-")
        })
        .map(|label| String::from_utf8_lossy(label).into_owned())
}

const LABEL_RULE: &str =
    "must be only ASCII letters, digits and hyphens, and not start or end with a hyphen";

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    fn names(list: &[&str]) -> Vec<Name> {
        list.iter().map(|n| name(n)).collect()
    }

    /// The aliases `list` parses to.
    fn aliases(list: &[&str]) -> Result<Vec<Name>, String> {
        parse(args(list)).map(|cli| cli.aliases)
    }

    #[test]
    fn parses_names_and_options() {
        let cli = parse(args(&[
            "app.local",
            "--interface",
            "enp1s0",
            "--interface",
            "wlo1",
            "media.local",
            "--require-sandbox",
        ]))
        .unwrap();
        assert_eq!(cli.interfaces, ["enp1s0", "wlo1"]);
        assert_eq!(cli.aliases, names(&["app.local", "media.local"]));
        assert!(cli.require_sandbox);
    }

    #[test]
    fn needs_at_least_one_name() {
        assert_eq!(parse(args(&[])), Err(USAGE.to_string()));
        assert_eq!(
            parse(args(&["--interface", "eth0"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn rejects_unknown_options_and_missing_values() {
        assert_eq!(parse(args(&["-v", "app.local"])), Err(USAGE.to_string()));
        assert_eq!(
            parse(args(&["app.local", "--interface"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn require_sandbox_is_off_unless_asked_for() {
        assert!(!parse(args(&["app.local"])).unwrap().require_sandbox);
        assert!(
            parse(args(&["--require-sandbox", "app.local"]))
                .unwrap()
                .require_sandbox
        );
    }

    #[test]
    fn the_removed_options_say_so() {
        for option in ["--cname", "--host", "--target"] {
            let expected = Err(format!(
                "{option} was removed: aliases are published as address records, \
                 and each is a full name ending in .local\n{USAGE}"
            ));
            assert_eq!(
                parse(args(&[option, "myhost.local", "app.local"])),
                expected
            );
            let joined = format!("{option}=myhost.local");
            assert_eq!(parse(args(&[&joined, "app.local"])), expected);
        }
        // Only those options: one that merely starts the same is unknown.
        assert_eq!(
            parse(args(&["--hostname", "app.local"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn a_name_without_local_is_refused_with_the_fix() {
        assert_eq!(
            aliases(&["app"]),
            Err("\"app\" is not a .local name; write app.local".to_string())
        );
        assert_eq!(
            aliases(&["app."]),
            Err("\"app.\" is not a .local name; write app.local".to_string())
        );
    }

    /// No suggestion where `<name>.local` would not be a sensible alias:
    /// several labels, `local` alone, or a label that fails the rules,
    /// which is reported as such.
    #[test]
    fn a_name_without_local_gets_no_suggestion_that_would_not_do() {
        for text in ["api.app", "app.example.com", "local", "LOCAL."] {
            assert_eq!(
                aliases(&[text]),
                Err(format!(
                    "{text:?} is not a .local name; an alias must end in .local"
                )),
            );
        }
        assert_eq!(
            aliases(&["my_app"]),
            Err("invalid name \"my_app\": label \"my_app\" must be only ASCII letters, digits and hyphens, and not start or end with a hyphen".to_string())
        );
    }

    #[test]
    fn the_own_name_is_the_first_label_of_the_host_name_under_local() {
        assert_eq!(own_name("myhost"), Some(name("myhost.local")));
        assert_eq!(own_name("MyHost.lan\n"), Some(name("myhost.local")));
        for bad in ["", "\n", "my_host", ".lan", "-x"] {
            assert_eq!(own_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_alias_that_is_this_machines_own_name_is_refused() {
        let list = names(&["app.local", "MyHost.local"]);
        assert_eq!(
            check_own_name(&list, Some("myhost.lan")),
            Err("MyHost.local is this machine's own name (myhost.local); its responder already publishes it".to_string())
        );
        assert_eq!(check_own_name(&list, Some("media")), Ok(()));
        // Several labels under the host name are other names.
        assert_eq!(
            check_own_name(&names(&["app.myhost.local"]), Some("myhost")),
            Ok(())
        );
        // No host name, or one that makes no valid name: no check.
        assert_eq!(check_own_name(&list, None), Ok(()));
        assert_eq!(check_own_name(&list, Some("my_host")), Ok(()));
    }

    #[test]
    fn names_are_used_as_given_and_may_have_several_labels() {
        assert_eq!(
            aliases(&["app.local", "api.app.local", "TV.Local", "media.local."]),
            Ok(names(&[
                "app.local",
                "api.app.local",
                "tv.local",
                "media.local"
            ]))
        );
    }

    #[test]
    fn duplicates_collapse_ignoring_case() {
        assert_eq!(
            aliases(&["app.local", "APP.local", "media.local", "App.Local."]),
            Ok(names(&["app.local", "media.local"]))
        );
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(
            aliases(&["app..local"]),
            Err("invalid name \"app..local\": empty label".to_string())
        );
        let long = format!("{}.local", vec!["a".repeat(60); 5].join("."));
        assert!(aliases(&[&long]).unwrap_err().contains("longer than 255"));
    }

    #[test]
    fn rejects_labels_that_are_not_host_names() {
        for bad in [
            "my_app.local",
            "my app.local",
            "x.-app.local",
            "app-.local",
            "bj\u{f6}rn.local",
            "a-.b.local",
            "app!.local",
        ] {
            let Err(err) = aliases(&[bad]) else {
                panic!("{bad:?} was accepted");
            };
            assert!(err.starts_with("invalid name \""), "{err}");
        }
    }

    #[test]
    fn the_label_error_names_the_label_and_the_full_name() {
        assert_eq!(
            aliases(&["my_app.local"]),
            Err("invalid name \"my_app.local\": label \"my_app\" must be only ASCII letters, digits and hyphens, and not start or end with a hyphen".to_string())
        );
    }

    #[test]
    fn accepts_digits_mixed_case_and_full_length_labels() {
        let long = format!("{}.local", "a".repeat(63));
        let parsed = aliases(&["8080.local", "Web-2.local", &long, "a-b-c.local"]).unwrap();
        assert_eq!(parsed.len(), 4);
    }
}
