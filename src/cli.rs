//! The command line, and the CNAME target it implies.

use crate::wire::Name;

pub const USAGE: &str =
    "usage: mdns-alias [--target <name.local>] [--interface <name>]... <alias.local>...";

#[derive(Debug, PartialEq)]
pub struct Cli {
    pub target: Option<Name>,
    /// `--interface` names; empty means the default set.
    pub interfaces: Vec<String>,
    /// Deduplicated, ignoring case.
    pub aliases: Vec<Name>,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let mut target = None;
    let mut interfaces = Vec::new();
    let mut aliases: Vec<Name> = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => target = Some(local_name(&args.next().ok_or(USAGE)?)?),
            "--interface" => interfaces.push(args.next().ok_or(USAGE)?),
            option if option.starts_with('-') => return Err(USAGE.into()),
            _ => {
                let alias = local_name(&arg)?;
                if !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
        }
    }
    if aliases.is_empty() {
        return Err(USAGE.into());
    }
    Ok(Cli {
        target,
        interfaces,
        aliases,
    })
}

/// The name every alias points at: `--target`, or else this host's own
/// `.local` name, made from the first label of `hostname` (the kernel host
/// name, when it could be read).
pub fn target(cli: &Cli, hostname: Option<&str>) -> Result<Name, String> {
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
    if let Some(alias) = cli.aliases.iter().find(|a| **a == target) {
        return Err(format!("{alias} is the target itself"));
    }
    Ok(target)
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

    #[test]
    fn parses_aliases_and_options() {
        let cli = parse(args(&[
            "--target",
            "myhost.local",
            "app.myhost.local",
            "--interface",
            "enp1s0",
            "--interface",
            "wlo1",
            "web.myhost.local",
        ]))
        .unwrap();
        assert_eq!(cli.target, Some(name("myhost.local")));
        assert_eq!(cli.interfaces, ["enp1s0", "wlo1"]);
        assert_eq!(
            cli.aliases,
            [name("app.myhost.local"), name("web.myhost.local")]
        );
    }

    #[test]
    fn needs_at_least_one_alias() {
        assert_eq!(parse(args(&[])), Err(USAGE.to_string()));
        assert_eq!(
            parse(args(&["--target", "myhost.local"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn rejects_unknown_options_and_missing_values() {
        assert_eq!(parse(args(&["-v", "app.local"])), Err(USAGE.to_string()));
        assert_eq!(
            parse(args(&["app.local", "--target"])),
            Err(USAGE.to_string())
        );
        assert_eq!(
            parse(args(&["app.local", "--interface"])),
            Err(USAGE.to_string())
        );
    }

    #[test]
    fn rejects_names_outside_local() {
        assert_eq!(
            parse(args(&["app.example.com"])),
            Err("app.example.com is not a .local name".to_string())
        );
        assert_eq!(
            parse(args(&["--target", "myhost", "app.local"])),
            Err("myhost is not a .local name".to_string())
        );
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(
            parse(args(&["app..local"])),
            Err("invalid name \"app..local\": empty label".to_string())
        );
    }

    #[test]
    fn dedupes_aliases_ignoring_case() {
        let cli = parse(args(&["app.local", "APP.local", "web.local"])).unwrap();
        assert_eq!(cli.aliases, [name("app.local"), name("web.local")]);
    }

    #[test]
    fn target_defaults_to_the_host_name() {
        let cli = parse(args(&["app.myhost.local"])).unwrap();
        assert_eq!(target(&cli, Some("myhost\n")), Ok(name("myhost.local")));
        assert_eq!(target(&cli, Some("myhost.lan")), Ok(name("myhost.local")));
    }

    #[test]
    fn target_option_wins_over_the_host_name() {
        let cli = parse(args(&["--target", "nas.local", "app.local"])).unwrap();
        assert_eq!(target(&cli, Some("myhost")), Ok(name("nas.local")));
        assert_eq!(target(&cli, None), Ok(name("nas.local")));
    }

    #[test]
    fn target_needs_a_host_name_or_the_option() {
        let cli = parse(args(&["app.local"])).unwrap();
        assert_eq!(
            target(&cli, None),
            Err("cannot read this host's name; pass --target <name.local>".to_string())
        );
        assert_eq!(
            target(&cli, Some("\n")),
            Err(
                "cannot make a .local name from host name \"\\n\"; pass --target <name.local>"
                    .to_string()
            )
        );
    }

    #[test]
    fn an_alias_cannot_be_the_target() {
        let cli = parse(args(&["MYHOST.local"])).unwrap();
        assert_eq!(
            target(&cli, Some("myhost")),
            Err("MYHOST.local is the target itself".to_string())
        );
    }
}
