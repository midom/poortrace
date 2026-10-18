#[unsafe(no_mangle)]
#[inline(never)]
pub fn native_rust(pair:(u64,u64),value:u64)->u64 {
    std::hint::black_box(pair.0)+std::hint::black_box(pair.1)+std::hint::black_box(value)
}
fn main(){std::hint::black_box(native_rust((11,22),33));}
