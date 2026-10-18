//! Opt-in native ABI tests; ordinary unit tests exercise register planning offline.
#[test]
#[ignore = "requires ptrace and a native C compiler"]
fn live_automatic_arguments_scalars_structures_vectors_and_stack() {
    let directory =
        std::env::temp_dir().join(format!("poortrace-arguments-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let image = directory.join("arguments");
    let status = std::process::Command::new("cc")
        .args(["-g", "-O0"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/arguments.c"
        ))
        .arg("-o")
        .arg(&image)
        .status()
        .unwrap();
    assert!(status.success());
    let path = image.display();
    let script = format!(
        "uprobe:{path}:inspect {{ printf(\"%s\\n\",args()); }} uprobe:{path}:spilled {{ printf(\"%s\\n\",args()); }} uprobe:{path}:aligned_hfa {{ printf(\"%s\\n\",args()); }} uprobe:{path}:union_hfa {{ printf(\"%s\\n\",args()); }} uprobe:{path}:nested_vector {{ printf(\"%s\\n\",args()); }} uprobe:{path}:vector_pair {{ printf(\"%s\\n\",args()); }} uprobe:{path}:returns_big {{ printf(\"%s\\n\",args()); }} uprobe:{path}:variadic {{ printf(\"%s\\n\",args_as(\"fixed=i32,...,small=i32,ratio=f64,large=i64\")); }}"
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "-e", &script, "--"])
        .arg(&image)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{text}\n{error}");
    for expected in [
        "small=-7",
        "ratio=1.25",
        "pair={integer: 42, floating: 2.5}",
        "hfa={first: 1, second: 2, third: 3}",
        "vector={[0]: 1.25, [1]: 2.5, [2]: 3.75, [3]: 4}",
        "big={first: 10, second: 20, third: 30}",
        "a0=1",
        "a8=9",
        "overlap={first: 1.25, second: 1.25}, afterunion=17",
        "padded={first: 1.25, second: 2.5, third: 3.75}, afterpadding=17",
        "spillvector={[0]: 1.25, [1]: 2.5, [2]: 3.75, [3]: 4}",
        "nested={first.[0]: 1.25, first.[1]: 2.5, first.[2]: 3.75, first.[3]: 4}, aftervector=17",
        "pair={first.[0]: 1, first.[1]: 2, first.[2]: 3, first.[3]: 4, second.[0]: 5, second.[1]: 6, second.[2]: 7, second.[3]: 8}, afterpair=19",
        "value=77, factor=2.5",
        "fixed=7, small=-3, ratio=1.25, large=99",
    ] {
        assert!(
            text.contains(expected),
            "missing {expected}: {text}\n{error}"
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires ptrace, rustc, and Go"]
fn live_native_dwarf_locations_decode_rust_and_go_without_c_abi_guesses() {
    let directory =
        std::env::temp_dir().join(format!("poortrace-native-arguments-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let rust = directory.join("rust");
    let go = directory.join("go");
    assert!(
        std::process::Command::new("rustc")
            .args(["-g", "-C", "opt-level=2", "-C", "force-frame-pointers=yes"])
            .arg(fixtures.join("native-arguments.rs"))
            .arg("-o")
            .arg(&rust)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("go")
            .args(["build", "-o"])
            .arg(&go)
            .arg(fixtures.join("native-arguments.go"))
            .status()
            .unwrap()
            .success()
    );
    for (image, function, expected) in [
        (&rust, "native_rust", "value=33"),
        (&go, "main.nativeGo", "first=11, second=22"),
    ] {
        let script = format!(
            "uprobe:{}:{function} {{printf(\"%s\\n\",args_native());}}",
            image.display()
        );
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_poortrace"))
            .args(["-q", "--no-print-maps", "-e", &script, "--"])
            .arg(image)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains(expected), "{function}: {stdout}\n{stderr}");
        if function == "native_rust" {
            assert!(stdout.contains("11") && stdout.contains("22"), "{stdout}");
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}
