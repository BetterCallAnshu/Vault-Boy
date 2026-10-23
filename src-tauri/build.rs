fn main() {
    let attributes = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("vaultly.manifest")),
    );
    tauri_build::try_build(attributes).expect("tauri-build failed");
}
