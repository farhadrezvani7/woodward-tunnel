// Windows: the engine needs Administrator to create the tunnel adapter, so the whole app asks for
// elevation at launch (see README, "Privileges").
const WINDOWS_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>"#;

// The third-party notices come from the repository root once the licensing work produces them;
// until then a placeholder is bundled so the About screen has something honest to show.
fn bundle_notices() {
    let root = std::path::Path::new("../../../THIRD-PARTY-NOTICES.md");
    let dest = std::path::Path::new("resources/THIRD-PARTY-NOTICES.md");
    println!("cargo:rerun-if-changed=../../../THIRD-PARTY-NOTICES.md");
    let text = std::fs::read(root).unwrap_or_else(|_| {
        b"Third-party notices were not available when this build was made.\nSee THIRD-PARTY-NOTICES.md in the source repository.\n".to_vec()
    });
    if std::fs::read(dest).ok().as_deref() != Some(&text[..]) {
        let _ = std::fs::write(dest, text);
    }
}

fn main() {
    bundle_notices();
    let mut attrs = tauri_build::Attributes::new();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        attrs = attrs.windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(WINDOWS_MANIFEST));
    }
    if let Err(e) = tauri_build::try_build(attrs) {
        panic!("tauri build failed: {e:#}");
    }
}
