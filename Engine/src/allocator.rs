/// Global heap allocator for no_std builds.
///
/// Uses a 4 MiB static byte array as the heap arena, backed by the Talc
/// allocator with a spin-lock for interrupt safety. This is sufficient for
/// LibAFL's internal allocations on baremetal targets.
///
/// If 4 MiB is too small for your target, increase `ARENA_SIZE`.

use core::alloc::GlobalAlloc;
use talc::{ClaimOnOom, Span, Talc};

const ARENA_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

static mut ARENA: [u8; ARENA_SIZE] = [0; ARENA_SIZE];

#[global_allocator]
static ALLOCATOR: Locked = Locked(spin::Mutex::new(unsafe {
    Talc::new(ClaimOnOom::new(Span::from_array(core::ptr::addr_of!(ARENA) as *mut [u8; ARENA_SIZE])))
}));

struct Locked(spin::Mutex<Talc<ClaimOnOom>>);

unsafe impl GlobalAlloc for Locked {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        match unsafe { self.0.lock().malloc(layout) } {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { self.0.lock().free(core::ptr::NonNull::new_unchecked(ptr), layout) }
    }
}
