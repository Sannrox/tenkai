//! Host settings read from the process environment: store and cache roots,
//! the state directory, and model-registry keys.
//!
//! Tests set these through [`overlay`] rather than the process environment,
//! which every test running concurrently in the process shares. An overlay is
//! per thread: `#[tokio::test]` runs its test, and the tasks it spawns, on
//! the test's own thread.

use std::ffi::OsString;

/// The setting `name`: a test overlay first, then the process environment.
pub fn var_os(name: &str) -> Option<OsString> {
    #[cfg(test)]
    if let Some(value) = overlay::get(name) {
        return value;
    }
    std::env::var_os(name)
}

/// [`var_os`] as a string, like [`std::env::var`].
pub fn var(name: &str) -> Result<String, std::env::VarError> {
    var_os(name)
        .ok_or(std::env::VarError::NotPresent)?
        .into_string()
        .map_err(std::env::VarError::NotUnicode)
}

#[cfg(test)]
pub mod overlay {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};

    thread_local! {
        static VALUES: RefCell<HashMap<String, Option<OsString>>> = RefCell::new(HashMap::new());
    }

    pub(super) fn get(name: &str) -> Option<Option<OsString>> {
        VALUES.with(|values| values.borrow().get(name).cloned())
    }

    /// Settings this thread sees until the guard drops; `None` reads as unset.
    pub fn set<'a>(settings: impl IntoIterator<Item = (&'a str, Option<&'a OsStr>)>) -> Scoped {
        let previous = settings
            .into_iter()
            .map(|(name, value)| {
                let before = VALUES.with(|values| {
                    values
                        .borrow_mut()
                        .insert(name.to_owned(), value.map(OsStr::to_owned))
                });
                (name.to_owned(), before)
            })
            .collect();
        Scoped {
            previous,
            _thread_bound: std::marker::PhantomData,
        }
    }

    /// Restores the settings it replaced when dropped.
    pub struct Scoped {
        previous: Vec<(String, Option<Option<OsString>>)>,
        _thread_bound: std::marker::PhantomData<*const ()>,
    }

    impl Drop for Scoped {
        fn drop(&mut self) {
            VALUES.with(|values| {
                let mut values = values.borrow_mut();
                for (name, before) in self.previous.drain(..).rev() {
                    match before {
                        Some(value) => values.insert(name, value),
                        None => values.remove(&name),
                    };
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overlay_is_seen_on_its_thread_only_and_restored() {
        let name = "TENKAI_HOST_ENV_OVERLAY_PROBE";
        {
            let _scope = overlay::set([(name, Some(std::ffi::OsStr::new("here")))]);
            assert_eq!(var(name).unwrap(), "here");
            std::thread::spawn(move || assert!(var(name).is_err()))
                .join()
                .unwrap();
            let _unset = overlay::set([(name, None)]);
            assert!(var(name).is_err());
        }
        assert!(var(name).is_err());
    }
}
