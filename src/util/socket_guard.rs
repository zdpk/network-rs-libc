pub struct SocketGuard(pub i32);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}
