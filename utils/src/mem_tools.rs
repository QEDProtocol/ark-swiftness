use log::{trace};
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
struct StatM {
    size: u64,
    resident: u64,
    share: u64,
    text: u64,
    lib: u64,
    data: u64,
    dt: u64,
}
impl From<String> for StatM {
    fn from(s: String) -> Self {
        let mut parts = s.split_whitespace();
        Self {
            size: parts.next().unwrap().parse().unwrap(),
            resident: parts.next().unwrap().parse().unwrap(),
            share: parts.next().unwrap().parse().unwrap(),
            text: parts.next().unwrap().parse().unwrap(),
            lib: parts.next().unwrap().parse().unwrap(),
            data: parts.next().unwrap().parse().unwrap(),
            dt: parts.next().unwrap().parse().unwrap(),
        }
    }
}
impl Display for StatM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "size={}, resident={}, share={}, text={}, lib={}, data={}, dt={}",
            self.size, self.resident, self.share, self.text, self.lib, self.data, self.dt
        )
    }
}
//        info!("Memory usage: size={}, resident={}, share={}, text={}, lib={}, data={}, dt={}",
pub fn print_memory_usage() {
    let mut file = File::open("/proc/self/statm").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("cannot read /proc/self/statm");
    let statm: StatM = contents.trim().to_string().into();
    trace!("Memory usage: {}", statm);
}
