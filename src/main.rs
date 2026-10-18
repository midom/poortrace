mod app;

fn main() {
    match app::run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("poortrace: {e}");
            std::process::exit(1);
        }
    }
}
