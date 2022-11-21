/// # Workaround
///
/// Provides workarounds to circumvent some limitations of Rust and/or
/// dependencies we use.
///
/// Currently libbpf_rs does not implement Send for many of its objects, while
/// for some of them it is actually safe. In the meantime, SendWrapper objects
/// can be used to send a non-Send libbpf_rs object to another thread.
///
/// For now we support SendWrapperMap.

/// SendWrapper<T> should not be used directly but only specific typedefs ones.
/// When adding a new SendWrapper type research should be done to ensure this is
/// actually safe!
///
/// SendWrapper<T> only implements the Send trait, if Sync is needed and more
/// than one user wants access use the common Arc<Mutex<SendWrapper<T>>>
/// construction (see core::workaround::tests::sync).
pub(crate) struct SendWrapper<T>(T)
where
    T: Sized + self::private::Sealed;

impl<T> SendWrapper<T>
where
    T: Sized + self::private::Sealed,
{
    /// Construct a new SendWrapper object given another (Sized) object that
    /// will become the inner object.
    pub(crate) fn from(obj: T) -> SendWrapper<T> {
        SendWrapper(obj)
    }

    /// Get a reference to the inner object.
    #[allow(dead_code)]
    pub(crate) fn get(&self) -> &T {
        &self.0
    }

    /// Get a mutable reference to the inner object.
    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

unsafe impl<T: self::private::Sealed> Send for SendWrapper<T> {}

// Define below types where it is actually safe to send them to another thread.
pub(crate) type SendableMap = SendWrapper<libbpf_rs::Map>;
pub(crate) type SendableRingBuffer<'a> = SendWrapper<libbpf_rs::RingBuffer<'a>>;

/// We use a sealed trait to restrict the use of SendWrapper to carefully
/// allowed types.
///
/// This is similar to (but here we're restricting a generic type):
/// https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
mod private {
    pub trait Sealed {}

    // Do not add anything else here unless:
    // 1. It is absolutely necessary! We reserve the right to refuse additions
    //    here for any reason.
    // 2. The long-term plan is to fix the upstream library.
    impl Sealed for libbpf_rs::Map {}
    impl Sealed for libbpf_rs::RingBuffer<'_> {}
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        thread,
    };

    use super::*;

    #[derive(Default)]
    struct DummyObject {
        a: u32,
    }

    impl private::Sealed for DummyObject {}

    #[test]
    fn send() {
        let mut sw = SendWrapper::from(DummyObject::default());
        let mut obj = sw.get_mut();
        obj.a = 42;

        // No need to test moving the above to > 1 thread fails as the compiler
        // will throw an error in such case (value used after move).
        let handle = thread::spawn(move || {
            let obj = sw.get_mut();
            assert!(obj.a == 42);
            obj.a += 1;
            assert!(obj.a == 43);
        });

        handle.join().unwrap();
    }

    #[test]
    fn sync() {
        let sw = Arc::new(Mutex::new(SendWrapper::from(DummyObject::default())));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let sw = Arc::clone(&sw);
            handles.push(thread::spawn(move || {
                let mut sw = sw.lock().unwrap();
                let obj = sw.get_mut();
                obj.a += 1;
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let sw = sw.lock().unwrap();
        let obj = sw.get();
        assert!(obj.a == 10);
    }
}
