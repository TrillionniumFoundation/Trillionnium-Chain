fn main() {
    let path = std::env::args_os().nth(1).expect("owned disposable fixture path");
    match validate_existing_store_path_v0(Path::new(&path)) {
        Ok(()) => println!("accepted"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(100);
        }
    }
}
