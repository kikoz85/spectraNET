//! Working out which user-facing application a process belongs to.
//!
//! Rules, in order:
//! 1. An executable inside an `.app` bundle belongs to the **outermost** bundle on its path,
//!    so `Google Chrome.app/…/Google Chrome Helper.app/…` belongs to Google Chrome.
//! 2. An XPC service outside any app bundle (e.g. under `/System/Library/Frameworks`) belongs
//!    to the application macOS holds *responsible* for it, if that one is an app bundle.
//! 3. Anything else (command-line tools, daemons) is its own application.
//!
//! "Responsibility" is deliberately not used for plain executables: macOS makes the terminal
//! responsible for every command run in it, and `curl` is not part of Terminal.
//!
//! The display name comes from the bundle's `Info.plist`, as the Finder shows it.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use spectranet_model::App;

/// Resolves and caches application membership.
#[derive(Default)]
pub struct AppResolver {
    names: HashMap<PathBuf, String>,
}

impl AppResolver {
    /// Returns the application owning `pid`, whose executable is at `exe_path`.
    pub fn resolve(&mut self, pid: u32, exe_path: &str) -> Option<App> {
        let exe = normalize(Path::new(exe_path));
        if let Some(bundle) = outermost_bundle(&exe) {
            let main = is_main_executable(&exe, &bundle);
            return Some(self.app_for(bundle, main));
        }
        if is_xpc_service(&exe) {
            let responsible = responsible_pid(pid)?;
            if responsible == pid {
                return None;
            }
            let owner = normalize(Path::new(&super::process_path(responsible)?));
            let bundle = outermost_bundle(&owner)?;
            return Some(self.app_for(bundle, false));
        }
        None
    }

    fn app_for(&mut self, bundle: PathBuf, main: bool) -> App {
        let name = self
            .names
            .entry(bundle.clone())
            .or_insert_with(|| display_name(&bundle))
            .clone();
        App {
            name,
            path: bundle.to_string_lossy().into_owned(),
            main,
        }
    }
}

/// Resolves `.` and `..` lexically, without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// The outermost `*.app` directory on the path, if any (the executable itself excluded).
fn outermost_bundle(exe: &Path) -> Option<PathBuf> {
    let mut prefix = PathBuf::new();
    let parent = exe.parent()?;
    for component in parent.components() {
        prefix.push(component);
        if has_extension(component, "app") {
            return Some(prefix);
        }
    }
    None
}

/// True for `<bundle>/Contents/MacOS/<executable>`.
fn is_main_executable(exe: &Path, bundle: &Path) -> bool {
    exe.parent() == Some(&bundle.join("Contents").join("MacOS"))
}

fn is_xpc_service(exe: &Path) -> bool {
    exe.components().any(|c| has_extension(c, "xpc"))
}

fn has_extension(component: Component<'_>, ext: &str) -> bool {
    match component {
        Component::Normal(name) => Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case(ext)),
        _ => false,
    }
}

/// `CFBundleDisplayName`, then `CFBundleName`, then the bundle's file name without `.app`.
fn display_name(bundle: &Path) -> String {
    let from_plist = plist::Value::from_file(bundle.join("Contents").join("Info.plist"))
        .ok()
        .and_then(|value| {
            let dict = value.into_dictionary()?;
            ["CFBundleDisplayName", "CFBundleName"]
                .iter()
                .find_map(|key| {
                    dict.get(key)
                        .and_then(plist::Value::as_string)
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                })
        });
    from_plist.unwrap_or_else(|| {
        bundle
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| bundle.to_string_lossy().into_owned())
    })
}

/// The process macOS holds responsible for `pid` (e.g. the app that launched an XPC service).
#[allow(unsafe_code)]
fn responsible_pid(pid: u32) -> Option<u32> {
    use std::sync::OnceLock;
    type Func = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;
    static FUNC: OnceLock<Option<Func>> = OnceLock::new();
    let func = (*FUNC.get_or_init(|| {
        // SAFETY: dlsym on the already-loaded system library; the symbol, when present, has
        // the signature `pid_t (pid_t)`.
        unsafe {
            let sym = libc::dlsym(
                libc::RTLD_DEFAULT,
                c"responsibility_get_pid_responsible_for_pid".as_ptr(),
            );
            (!sym.is_null()).then(|| std::mem::transmute::<*mut libc::c_void, Func>(sym))
        }
    }))?;
    // SAFETY: plain integer in, integer out; returns -1 for unknown processes.
    let responsible = unsafe { func(libc::pid_t::try_from(pid).ok()?) };
    u32::try_from(responsible).ok().filter(|&p| p > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_HELPER: &str = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154.0.8037.98/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper";

    #[test]
    fn helper_belongs_to_outermost_bundle() {
        let exe = normalize(Path::new(CHROME_HELPER));
        let bundle = outermost_bundle(&exe).unwrap();
        assert_eq!(bundle, Path::new("/Applications/Google Chrome.app"));
        assert!(!is_main_executable(&exe, &bundle));
    }

    #[test]
    fn main_executable_is_detected() {
        let exe = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        let bundle = outermost_bundle(exe).unwrap();
        assert!(is_main_executable(exe, &bundle));
    }

    #[test]
    fn parent_dir_components_are_resolved() {
        // Real path reported for the Creative Cloud synchroniser.
        let raw = "/Library/Application Support/Adobe/Creative Cloud Libraries/CCLibrary.app/Contents/MacOS/../libs/Creative Cloud Libraries Synchronizer";
        let exe = normalize(Path::new(raw));
        assert_eq!(
            exe,
            Path::new(
                "/Library/Application Support/Adobe/Creative Cloud Libraries/CCLibrary.app/Contents/libs/Creative Cloud Libraries Synchronizer"
            )
        );
        let bundle = outermost_bundle(&exe).unwrap();
        assert!(bundle.ends_with("CCLibrary.app"));
        assert!(!is_main_executable(&exe, &bundle));
    }

    #[test]
    fn plain_tools_have_no_bundle() {
        for exe in ["/usr/bin/ssh", "/opt/homebrew/bin/node", "ssh", "/", ""] {
            assert_eq!(outermost_bundle(Path::new(exe)), None, "{exe}");
        }
    }

    #[test]
    fn bundle_must_be_a_directory_on_the_path_not_the_executable() {
        // An executable literally named "x.app" is not inside a bundle.
        assert_eq!(outermost_bundle(Path::new("/usr/local/bin/x.app")), None);
    }

    #[test]
    fn extension_match_is_case_insensitive_and_exact() {
        assert!(outermost_bundle(Path::new("/Apps/Weird.APP/Contents/MacOS/w")).is_some());
        assert!(outermost_bundle(Path::new("/Apps/notapp/Contents/MacOS/w")).is_none());
        assert!(outermost_bundle(Path::new("/Apps/my.application/bin/w")).is_none());
    }

    #[test]
    fn xpc_services_are_recognised() {
        assert!(is_xpc_service(Path::new(
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
        )));
        assert!(!is_xpc_service(Path::new("/usr/libexec/xpcproxy")));
    }

    #[test]
    fn display_name_prefers_plist_then_file_name() {
        let dir = std::env::temp_dir().join(format!("snet-apps-{}", std::process::id()));
        let with_display = dir.join("Odd Folder Name.app");
        let with_name = dir.join("Other.app");
        let without_plist = dir.join("Bare Name.app");
        let empty_names = dir.join("Empty.app");
        for bundle in [&with_display, &with_name, &without_plist, &empty_names] {
            std::fs::create_dir_all(bundle.join("Contents")).unwrap();
        }
        let write = |bundle: &Path, entries: &[(&str, &str)]| {
            let mut dict = plist::Dictionary::new();
            for (k, v) in entries {
                dict.insert((*k).into(), plist::Value::String((*v).into()));
            }
            plist::to_file_xml(bundle.join("Contents/Info.plist"), &dict).unwrap();
        };
        write(
            &with_display,
            &[
                ("CFBundleDisplayName", "Pretty Name"),
                ("CFBundleName", "Short"),
            ],
        );
        write(&with_name, &[("CFBundleName", "  Named  ")]);
        write(
            &empty_names,
            &[("CFBundleDisplayName", " "), ("CFBundleName", "")],
        );

        assert_eq!(display_name(&with_display), "Pretty Name");
        assert_eq!(display_name(&with_name), "Named");
        assert_eq!(display_name(&without_plist), "Bare Name");
        assert_eq!(display_name(&empty_names), "Empty");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_plist_falls_back_to_file_name() {
        let dir = std::env::temp_dir().join(format!("snet-apps-corrupt-{}", std::process::id()));
        let bundle = dir.join("Broken.app");
        std::fs::create_dir_all(bundle.join("Contents")).unwrap();
        std::fs::write(bundle.join("Contents/Info.plist"), b"\x00not a plist").unwrap();
        assert_eq!(display_name(&bundle), "Broken");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resolves_a_real_system_app() {
        let mut resolver = AppResolver::default();
        let app = resolver
            .resolve(
                1,
                "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
            )
            .unwrap();
        assert_eq!(app.name, "Calculator");
        assert_eq!(app.path, "/System/Applications/Calculator.app");
        assert!(app.main);
    }

    #[test]
    fn command_line_tools_stand_alone() {
        let mut resolver = AppResolver::default();
        assert_eq!(resolver.resolve(std::process::id(), "/usr/bin/curl"), None);
    }

    #[test]
    fn responsibility_lookup_handles_bad_pids() {
        assert_eq!(responsible_pid(u32::MAX), None);
        assert!(responsible_pid(std::process::id()).is_some());
    }
}
