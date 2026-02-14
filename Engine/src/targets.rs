/// C ABI function pointer types for fuzz targets.

/// Target that receives a byte buffer and its length.
pub type CTargetFn = unsafe extern "C" fn(*const u8, usize);

/// Target that receives a null-terminated C string.
pub type CTargetStringFn = unsafe extern "C" fn(*const core::ffi::c_char);
