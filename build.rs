use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("Failed to get OUT_DIR");

    fn copy_file(out_dir: &str, file_name: &str) {
        let dest_path = Path::new(out_dir)
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .unwrap()
            .join(file_name);

        fs::copy(file_name, &dest_path)
            .unwrap_or_else(|_| panic!("Failed to copy {} to {:?}", file_name, dest_path));
    }
    copy_file(&out_dir, "config.json");
    copy_file(&out_dir, "websites.txt");
}
