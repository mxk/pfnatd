use crate::pf::Pf;
use crate::pflog::Pflog;
use anyhow::Result;

mod pf;
mod pflog;
mod sys;

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info) // TODO: Reset to Warn
        .parse_default_env()
        .init();

    let _pf = Pf::open()?;
    let mut pflog = Pflog::open("pflog0")?;

    // TODO: Replace
    let intr = pflog.interrupt();
    ctrlc::set_handler(move || drop(intr.clone())).expect("Failed to set Ctrl-C handler");

    loop {
        let p = pflog.next()?;
        println!("{p}");
        if let Some(stun) = p.stun_nat() {
            println!("  {stun}");
        }
    }
}
