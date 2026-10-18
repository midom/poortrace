//! Explicit event-time memory regions for offline re-analysis.
use crate::{Result, recording::MemoryRegion, runtime::Event};
use std::str::FromStr;

#[derive(Clone, Debug)]
enum Address {
    Literal(u64),
    Argument(usize),
    Stack,
    Ip,
}
#[derive(Clone, Debug)]
pub struct MemoryRequest {
    address: Address,
    length: usize,
}
impl FromStr for MemoryRequest {
    type Err = String;
    fn from_str(text: &str) -> Result<Self> {
        let (address, length) = text
            .rsplit_once(':')
            .ok_or("memory capture needs ADDRESS:LENGTH or arg0:LENGTH")?;
        let length = length.parse::<usize>().map_err(|e| e.to_string())?;
        if !(1..=4096).contains(&length) {
            return Err("each captured memory region needs 1..4096 bytes".into());
        }
        let address = match address {
            "sp" => Address::Stack,
            "ip" => Address::Ip,
            value if value.starts_with("arg") => {
                let index = value[3..].parse::<usize>().map_err(|e| e.to_string())?;
                if index >= 6 {
                    return Err("memory capture argument must be arg0..arg5".into());
                }
                Address::Argument(index)
            }
            value => Address::Literal(
                if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    value.parse()
                }
                .map_err(|e| e.to_string())?,
            ),
        };
        Ok(Self { address, length })
    }
}
pub fn capture(
    requests: &[MemoryRequest],
    event: &Event<'_>,
    sp: Option<u64>,
) -> Result<Vec<MemoryRegion>> {
    if requests.len() > 256 || requests.iter().map(|r| r.length).sum::<usize>() > 256 * 1024 {
        return Err("memory capture exceeds 256 regions/256 KiB per observation".into());
    }
    requests
        .iter()
        .map(|request| {
            let address = match request.address {
                Address::Literal(value) => value,
                Address::Argument(index) => event.args[index],
                Address::Ip => event.ip,
                Address::Stack => sp.ok_or("stack register unavailable for memory capture")?,
            };
            let bytes = crate::memory::read(event.pid as u32, address, request.length, false)?;
            Ok(MemoryRegion { address, bytes })
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captures_named_arguments_with_independent_region_bounds() {
        let data = [17u64, 42];
        let mut event = Event::new(c"fixture", c"BEGIN");
        event.pid = std::process::id() as u64;
        event.args[0] = data.as_ptr() as u64;
        let regions = capture(&["arg0:16".parse().unwrap()], &event, None).unwrap();
        assert_eq!(
            regions[0].bytes,
            data.into_iter()
                .flat_map(u64::to_ne_bytes)
                .collect::<Vec<_>>()
        );
        for bad in [
            "arg6:8",
            "arg0:4097",
            "sp:0",
            "no-address",
            "0xffffffffffffffff:8",
        ] {
            match bad.parse::<MemoryRequest>() {
                Err(_) => {}
                Ok(request) => assert!(capture(&[request], &event, None).is_err()),
            }
        }
    }
}
