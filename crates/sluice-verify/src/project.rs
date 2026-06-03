//! Foundry skeleton emission (`emit_poc_project`).
//!
//! Writes a drop-in `sluice-poc/` project: `foundry.toml`, `remappings.txt`, a
//! `README.md` stating each PoC's tier + the honesty limits, and one
//! `test/F-XXX_<slug>.t.sol` per PoC'd finding. Sluice never runs `forge`; the
//! README tells the user how (`forge install foundry-rs/forge-std`, point
//! remappings at the target repo, `forge test`).

use crate::context::sanitize_ident;
use crate::{generate_poc, poc_tier};
use sluice_findings::Finding;
use sluice_ir::Scir;
use std::io::Write;
use std::path::{Path, PathBuf};

const FOUNDRY_TOML: &str = "\
[profile.default]\n\
src = \"src\"\n\
out = \"out\"\n\
libs = [\"lib\"]\n\
test = \"test\"\n\
# Sluice PoCs import the target by relative path; some need IR codegen.\n\
# via_ir = true\n";

const REMAPPINGS: &str = "\
forge-std/=lib/forge-std/src/\n";

/// Emit the skeleton. Returns the absolute-ish paths written, `sluice-poc/`
/// rooted under `out_dir`.
pub fn emit(
    scir: &Scir,
    findings: &[Finding],
    out_dir: &Path,
    top_n: usize,
) -> std::io::Result<Vec<PathBuf>> {
    let root = out_dir.join("sluice-poc");
    let test_dir = root.join("test");
    std::fs::create_dir_all(&test_dir)?;

    let mut written = Vec::new();

    // Static skeleton files.
    let toml = root.join("foundry.toml");
    write_file(&toml, FOUNDRY_TOML)?;
    written.push(toml);

    let remap = root.join("remappings.txt");
    write_file(&remap, REMAPPINGS)?;
    written.push(remap);

    // One test file per PoC'd finding (top-N by the caller's ordering).
    let mut readme_rows = String::new();
    for f in findings.iter().take(top_n) {
        let tier = poc_tier(scir, f);
        let slug = f.category.slug().replace('-', "_");
        let fname = format!("{}_{}_{}.t.sol", sanitize_id(&f.id), sanitize_ident(&f.contract), slug);
        let path = test_dir.join(&fname);
        let poc = generate_poc(scir, f);
        write_file(&path, &poc)?;
        readme_rows.push_str(&format!(
            "| `{}` | {} | `{}` | {} | `test/{}` |\n",
            f.id,
            f.severity.label(),
            f.category.slug(),
            tier.tag(),
            fname,
        ));
        written.push(path);
    }

    let readme = root.join("README.md");
    write_file(&readme, &readme_md(&readme_rows))?;
    written.push(readme);

    Ok(written)
}

fn write_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(content.as_bytes())
}

/// `F-001` → `F-001` but identifier-safe for a filename (`-` kept, it's fine in
/// a path; we only strip anything exotic).
fn sanitize_id(id: &str) -> String {
    let out: String = id.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').collect();
    if out.is_empty() { "F-000".to_string() } else { out }
}

fn readme_md(rows: &str) -> String {
    format!(
        "# Sluice — generated Foundry PoCs\n\n\
         These proof-of-concept tests were generated **statically** by Sluice. \
         Sluice never runs `forge`; you run it. \"Compiles\" here means *the harness \
         is syntactically valid and self-consistent given the target source resolves \
         its own imports* — not that Sluice executed it.\n\n\
         ## Honesty tiers\n\n\
         | Tier | Meaning |\n\
         |------|---------|\n\
         | `poc:tier1` | Compiling exploit harness — valid given the target resolves its imports. |\n\
         | `poc:tier2` | Compiling skeleton + asserted hypothesis — fill the `/* FILL */` constants (ctor wiring, pool address, message struct). |\n\
         | `poc:tier3` | Trace-annotated stub — NOT claimed to compile; complete the TODOs. |\n\n\
         ## PoCs in this project\n\n\
         | Finding | Severity | Category | Tier | File |\n\
         |---------|----------|----------|------|------|\n\
         {rows}\n\
         ## How to run\n\n\
         ```sh\n\
         # 1. Install forge-std (the only hard dependency of the harnesses).\n\
         forge install foundry-rs/forge-std\n\n\
         # 2. Make the target source importable. The tests import it by a relative\n\
         #    path computed from where Sluice found it (e.g. `../../src/Vault.sol`).\n\
         #    Either copy this `sluice-poc/` dir into the target repo root, or add a\n\
         #    remapping in `remappings.txt` pointing at the target sources, e.g.:\n\
         #      @target/=../path/to/target/src/\n\
         #    and adjust the `import` line in the test accordingly.\n\n\
         # 3. Run a single PoC (red -> green proves the exploit).\n\
         forge test --match-path 'test/F-*' -vvv\n\
         ```\n\n\
         ## Limits (the realistic static ceiling)\n\n\
         - Sluice is static-only and does **not** orchestrate builds — it cannot \
         resolve the target's own dependency tree, so a project compile depends on \
         the target resolving its imports.\n\
         - Constructor and external-wiring unknowns are the dominant reason a PoC is \
         Tier 2 rather than Tier 1; the `/* FILL */` placeholders keep the file \
         compiling while you supply them.\n\
         - One template covers a *family*, not a specific finding: the exploit \
         *hypothesis* is asserted, but protocol-specific profit magnitude (oracle \
         over-borrow, bridge message struct) still needs your final `assert`.\n"
    )
}
