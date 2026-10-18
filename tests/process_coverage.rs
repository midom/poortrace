use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

#[test]
fn discovers_children_that_predate_attachment() {
    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & echo $!; wait"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let grandchild: i32 = line.trim().parse().unwrap();
    let found = poortrace::syscall::descendants(child.id() as i32).unwrap();
    unsafe {
        libc::kill(grandchild, libc::SIGKILL);
    }
    let _ = child.wait();
    assert!(found.contains(&grandchild));
}

#[test]
#[ignore = "requires ptrace access and a C compiler"]
fn attaches_existing_tree_with_syscalls_and_function_probes() {
    let dir = std::env::temp_dir().join(format!("poortrace-existing-tree-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("tree.c");
    let binary = dir.join("tree");
    std::fs::write(&source,r#"
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
__attribute__((noinline)) void observed(void) { write(2,"tick\n",5); }
int main(void) {
 prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
 pid_t child=fork();
 if (!child) { prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0); for(;;) { observed(); usleep(10000); } }
 printf("%d\n",child); fflush(stdout);
 for(;;) { observed(); usleep(10000); }
}
"#).unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let mut target = Command::new(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(target.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let descendant: i32 = line.trim().parse().unwrap();
    let root = target.id().to_string();
    let mut results = Vec::new();
    for script in [
        "syscall:enter:write { printf(\"seen:%d\\n\",pid); }".to_string(),
        format!(
            "uprobe:{}:observed {{ printf(\"seen:%d\\n\",pid); }}",
            binary.display()
        ),
    ] {
        results.push(
            Command::new(env!("CARGO_BIN_EXE_poortrace"))
                .args([
                    "-q",
                    "-p",
                    &root,
                    "--attach-descendants",
                    "-d",
                    "0.15",
                    "-e",
                    &script,
                ])
                .output()
                .unwrap(),
        );
    }
    // Attached targets must survive both tracer detach paths.
    let parent_alive = unsafe { libc::kill(target.id() as i32, 0) } == 0;
    let child_alive = unsafe { libc::kill(descendant, 0) } == 0;
    unsafe {
        libc::kill(descendant, libc::SIGKILL);
    }
    let _ = target.kill();
    let _ = target.wait();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(parent_alive && child_alive);
    for result in results {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let out = String::from_utf8_lossy(&result.stdout);
        assert!(out.contains(&format!("seen:{root}\n")), "{out}");
        assert!(out.contains(&format!("seen:{descendant}\n")), "{out}");
    }
}

#[test]
#[ignore = "requires ptrace access and a C compiler"]
fn tracks_short_lived_library_mappings_at_syscall_stops() {
    let dir = std::env::temp_dir().join(format!("poortrace-loader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let library = dir.join("brief.so");
    let driver = dir.join("driver");
    let source = dir.join("library.c");
    std::fs::write(
        &source,
        "__attribute__((noinline)) int brief(int x) { return x+1; }\n",
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-shared", "-fPIC"])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(&source,r#"
#include <dlfcn.h>
int main(int argc,char **argv) {
 for(int i=0;i<3;i++) { void *h=dlopen(argv[1],RTLD_NOW); if(!h)return 2; int (*f)(int)=dlsym(h,"brief"); if(!f || f(i)!=i+1)return 3; dlclose(h); } return 0;
}
"#).unwrap();
    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-ldl")
            .arg("-o")
            .arg(&driver)
            .status()
            .unwrap()
            .success()
    );
    let script = format!("uprobe:{}:brief {{ @calls = count(); }}", library.display());
    let result = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--track-loads", "-e", &script, "--"])
        .arg(&driver)
        .arg(&library)
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("@calls: 3"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
#[ignore = "requires ptrace access and a C compiler"]
fn prunes_abandoned_returns_after_nonlocal_unwind() {
    let dir = std::env::temp_dir().join(format!("poortrace-unwind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("unwind.c");
    let binary = dir.join("unwind");
    std::fs::write(&source,r#"
#include <setjmp.h>
static jmp_buf env;
static int abort_call;
__attribute__((noinline)) int leaf(void) { if(abort_call)longjmp(env,1); return 17; }
__attribute__((noinline)) int middle(void) { volatile char space[4096]; space[0]=1; return leaf()+space[0]; }
__attribute__((noinline)) int resumed(void) { return 3; }
int main(void) { abort_call=1; if(!setjmp(env))middle(); resumed(); abort_call=0; return middle()!=18; }
"#).unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let script = format!(
        "uretprobe:{}:leaf {{ @returns=count(); }} uprobe:{}:resumed {{ @resumed=count(); }}",
        binary.display(),
        binary.display()
    );
    let result = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "-e", &script, "--"])
        .arg(&binary)
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("@returns: 1"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
#[ignore = "requires ptrace access and a C compiler"]
fn restores_temporarily_nonexecutable_function_pages() {
    let dir = std::env::temp_dir().join(format!("poortrace-protect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let library = dir.join("protect.so");
    let driver = dir.join("driver");
    let source = dir.join("protect.c");
    std::fs::write(
        &source,
        "__attribute__((noinline)) int protected_call(int x) { return x+7; }\n",
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-shared", "-fPIC"])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        &source,
        r#"
#include <dlfcn.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
int main(int argc,char **argv) {
 void *h=dlopen(argv[1],RTLD_NOW); if(!h)return 2;
 int (*f)(int)=dlsym(h,"protected_call"); if(!f || f(1)!=8)return 3;
 long size=sysconf(_SC_PAGESIZE); void *page=(void *)((uintptr_t)f & ~((uintptr_t)size-1));
 if(mprotect(page,size,PROT_READ))return 4;
 if(mprotect(page,size,PROT_READ|PROT_EXEC))return 5;
 if(f(2)!=9)return 6;
 return 0;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-ldl")
            .arg("-o")
            .arg(&driver)
            .status()
            .unwrap()
            .success()
    );
    let script = format!(
        "uprobe:{}:protected_call {{ @calls=count(); }}",
        library.display()
    );
    let result = Command::new(env!("CARGO_BIN_EXE_poortrace"))
        .args(["-q", "--track-loads", "-e", &script, "--"])
        .arg(&driver)
        .arg(&library)
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("@calls: 2"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}
