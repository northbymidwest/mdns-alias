//! The command line, and the CNAME target it implies.

use crate::wire::Name;

pub const USAGE: &str = "usage: mdns-alias [--target <name.local>] [--interface <name>]... [--require-sandbox] <name>...";

#[derive(Debug, PartialEq)]
pub struct Cli {
    pub target: Option<Name>,
    /// `--interface` names; empty means the default set.
    pub interfaces: Vec<String>,
    /// The names as given: relative to the target unless they end in
    /// `.local` (or a dot). `resolve` expands them.
    pub names: Vec<String>,
    /// Exit rather than run with any sandbox layer missing.
    pub require_sandbox: bool,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let mut target = None;
    let mut interfaces = Vec::new();
    let mut names = Vec::new();
    let mut require_sandbox = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => target = Some(local_name(&args.next().ok_or(USAGE)?)?),
            "--interface" => interfaces.push(args.next().ok_or(USAGE)?),
            "--require-sandbox" => require_sandbox = true,
            option if option.starts_with('-') => return Err(USAGE.into()),
            _ => names.push(arg),
        }
    }
    if names.is_empty() {
        return Err(USAGE.into());
    }
    Ok(Cli {
        target,
        interfaces,
        names,
        require_sandbox,
    })
}

/// The target every alias points at, and the aliases, deduplicated ignoring
/// case. The target is `--target`, or else this host's own `.local` name,
/// made from the first label of `hostname` (the kernel host name, when it
/// could be read). Relative names are expanded under it.
pub fn resolve(cli: &Cli, hostname: Option<&str>) -> Result<(Name, Vec<Name>), String> {
    let target = match (&cli.target, hostname) {
        (Some(target), _) => target.clone(),
        (None, Some(host)) => {
            let first = host.trim().split('.').next().unwrap_or_default();
            Name::parse(&format!("{first}.local")).map_err(|_| {
                format!(
                    "cannot make a .local name from host name {host:?}; pass --target <name.local>"
                )
            })?
        }
        (None, None) => {
            return Err("cannot read this host's name; pass --target <name.local>".into());
        }
    };
    let mut aliases: Vec<Name> = Vec::new();
    for text in &cli.names {
        let alias = alias(text, &target)?;
        if alias == target {
            return Err(format!("{alias} is the target itself"));
        }
        if !aliases.contains(&alias) {
            aliases.push(alias);
        }
    }
    Ok((target, aliases))
}

/// `text` as a full name. Absolute if it ends in `.local`, or in a dot as
/// in DNS; otherwise relative, under `target`: `seerr` is
/// `seerr.<target>`.
fn alias(text: &str, target: &Name) -> Result<Name, String> {
    if text.ends_with('.') {
        return local_name(text);
    }
    let name = Name::parse(text).map_err(|e| format!("invalid name {text:?}: {e}"))?;
    if name.is_local() {
        return Ok(name);
    }
    name.under(target)
        .map_err(|e| format!("invalid name {text:?} under {target}: {e}"))
}

fn local_name(text: &str) -> Result<Name, String> {
    let name = Name::parse(text).map_err(|e| format!("invalid name {text:?}: {e}"))?;
    if !name.is_local() {
        return Err(format!("{name} is not a .local name"));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    /// Parses `list`, then resolves it against the host name `myhost`.
    fn resolved(list: &[&str]) -> Result<(Name, Vec<Name>), String> {
        resolve(&parse(args(list))?, Some("myhost\n"))
    }

    fn names(list: &[&str]) -> Vec<Name> {
        list.iter().map(|n| name(n)).collect()
    }

    #[test]
    fn parses_names_and_options() {
        let cli = parse(args(&[
            "--target",
            "myhost.local",
            "seerr",
            "--interface",
            "enp1s0",
            "--interface",
            "wlo1",
            "app.other.local",
            "--require-sandbox",
        ]))
        .unwrap();
        assert_eq!(cli.target, Some(name("myhost.local")));
        assert_eq!(cli.interfaces, ["enp1s0", "wlo1"]);
        assert_eq!(cli.names, ["seerr", "app.other.local"]);
        assert!(cli.require_sandbox);
    }

    #[test]
    fn needs_at_least_one_name() {
        assert_eq!(parse(args(&[])), Err(USAGE.to_string()));
        assert_eq!(
            parse(args(&["--target", "myhost.local"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn rejects_unknown_options_and_missing_values() {
        assert_eq!(parse(args(&["-v", "seerr"])), Err(USAGE.to_string()));
        assert_eq!(parse(args(&["seerr", "--target"])), Err(USAGE.to_string()));
        assert_eq!(
            parse(args(&["seerr", "--interface"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn require_sandbox_is_off_unless_asked_for() {
        assert!(!parse(args(&["seerr"])).unwrap().require_sandbox);
        assert!(
            parse(args(&["--require-sandbox", "seerr"]))
                .unwrap()
                .require_sandbox
        );
    }

    #[test]
    fn the_target_must_be_a_local_name() {
        assert_eq!(
            parse(args(&["--target", "myhost", "seerr"])),
            Err("myhost is not a .local name".to_string())
        );
    }

    #[test]
    fn names_without_local_are_relative_to_the_target() {
        let (target, aliases) = resolved(&["seerr", "api.seerr"]).unwrap();
        assert_eq!(target, name("myhost.local"));
        assert_eq!(
            aliases,
            names(&["seerr.myhost.local", "api.seerr.myhost.local"])
        );
    }

    #[test]
    fn names_ending_in_local_are_absolute() {
        let (_, aliases) = resolved(&["app.other.local", "seerr", "TV.Local"]).unwrap();
        assert_eq!(
            aliases,
            names(&["app.other.local", "seerr.myhost.local", "tv.local"])
        );
    }

    #[test]
    fn relative_names_follow_the_target_option() {
        let (target, aliases) = resolved(&["--target", "nas.local", "files"]).unwrap();
        assert_eq!(target, name("nas.local"));
        assert_eq!(aliases, names(&["files.nas.local"]));
    }

    #[test]
    fn a_trailing_dot_makes_a_name_absolute() {
        let (_, aliases) = resolved(&["app.other.local."]).unwrap();
        assert_eq!(aliases, names(&["app.other.local"]));
        assert_eq!(
            resolved(&["seerr."]),
            Err("seerr is not a .local name".to_string())
        );
    }

    #[test]
    fn duplicates_collapse_across_forms_ignoring_case() {
        let (_, aliases) = resolved(&["seerr", "SEERR.myhost.local", "Seerr", "sonarr"]).unwrap();
        assert_eq!(
            aliases,
            names(&["seerr.myhost.local", "sonarr.myhost.local"])
        );
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(
            resolved(&["app..local"]),
            Err("invalid name \"app..local\": empty label".to_string())
        );
        assert_eq!(
            resolved(&["a..b"]),
            Err("invalid name \"a..b\": empty label".to_string())
        );
    }

    #[test]
    fn rejects_relative_names_too_long_once_expanded() {
        // Four 60-byte labels fit 255 bytes alone (245), not with
        // ".myhost.local" appended.
        let long = vec!["a".repeat(60); 4].join(".");
        assert!(Name::parse(&long).is_ok());
        assert_eq!(
            resolved(&[&long]),
            Err(format!(
                "invalid name {long:?} under myhost.local: name longer than 255 bytes"
            ))
        );
    }

    #[test]
    fn target_defaults_to_the_host_name() {
        let cli = parse(args(&["seerr"])).unwrap();
        assert_eq!(
            resolve(&cli, Some("myhost.lan")).unwrap().0,
            name("myhost.local")
        );
    }

    #[test]
    fn target_needs_a_host_name_or_the_option() {
        let cli = parse(args(&["seerr"])).unwrap();
        assert_eq!(
            resolve(&cli, None),
            Err("cannot read this host's name; pass --target <name.local>".to_string())
        );
        assert_eq!(
            resolve(&cli, Some("\n")),
            Err(
                "cannot make a .local name from host name \"\\n\"; pass --target <name.local>"
                    .to_string()
            )
        );
    }

    #[test]
    fn an_alias_cannot_be_the_target() {
        assert_eq!(
            resolved(&["MYHOST.local"]),
            Err("MYHOST.local is the target itself".to_string())
        );
    }
}
