use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::str;

use anyhow::{Context, Result, ensure};

use crate::{Audit, Location};

fn git(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(["--no-pager", "--no-replace-objects"])
        .args(["-c", "core.fsmonitor=false", "-c", "log.showSignature=false"])
        .env_remove("BASSET_HMAC_KEY").env_remove("CREDCHECK_HMAC_KEY")
        .env("GIT_ALLOW_PROTOCOL", "").env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0").env("GIT_OPTIONAL_LOCKS", "0")
        .stderr(Stdio::null()).stdin(Stdio::null()).stdout(Stdio::piped());
    cmd
}

fn metadata<T>(repo: &Path, args: &[&str], consume: impl FnOnce(BufReader<ChildStdout>) -> Result<T>) -> Result<T> {
    let mut child = git(repo).args(args).spawn().context("starting Git")?;
    let reader = BufReader::new(child.stdout.take().context("missing Git stdout")?);
    let result = consume(reader);
    if result.is_err() { let _ = child.kill(); }
    let status = child.wait()?;
    let value = result?;
    ensure!(status.success(), "Git {} failed", args[0]);
    Ok(value)
}

struct Objects {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Objects {
    fn open(repo: &Path) -> Result<Self> {
        let mut child = git(repo).args(["cat-file", "--batch-command"]).stdin(Stdio::piped()).spawn()?;
        let input = child.stdin.take().context("missing object input")?;
        let output = BufReader::new(child.stdout.take().context("missing object output")?);
        Ok(Self { child, input, output })
    }

    fn query(&mut self, action: &str, oid: &str) -> Result<u64> {
        writeln!(self.input, "{action} {oid}")?;
        self.input.flush()?;
        let mut header = String::new();
        self.output.read_line(&mut header)?;
        let mut fields = header.split_whitespace();
        ensure!(fields.next() == Some(oid) && fields.next() == Some("blob"), "missing local Git blob");
        Ok(fields.next().context("missing blob size")?.parse()?)
    }

    fn scan<W: Write>(&mut self, oid: &str, loc: Location<'_>, audit: &mut Audit<W>) -> Result<()> {
        let size = self.query("info", oid)?;
        if size > audit.limit { return audit.skip(&loc, "Git blob exceeds --max-bytes"); }
        ensure!(self.query("contents", oid)? == size, "inconsistent Git blob size");
        let mut bytes = vec![0; usize::try_from(size)?];
        self.output.read_exact(&mut bytes)?;
        let mut newline = [0u8];
        self.output.read_exact(&mut newline)?;
        ensure!(newline == [b'\n'], "invalid Git object framing");
        audit.document(loc, &bytes)
    }
}

impl Drop for Objects {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|c| c.is_ascii_hexdigit())
}

struct History<'a, W> {
    repo: &'a Path,
    source: &'a str,
    objects: Objects,
    seen: HashSet<(String, String)>,
    audit: &'a mut Audit<W>,
}

impl<W: Write> History<'_, W> {
    fn changes(&mut self, revision: Option<&str>) -> Result<()> {
        let mut args = match revision {
            Some(_) => vec!["diff-tree", "--root", "-r", "-m", "--no-commit-id"],
            None => vec!["diff", "--cached"],
        };
        args.extend(["--raw", "-z", "--no-abbrev", "--no-renames", "--no-relative",
            "--no-ext-diff", "--no-textconv", "--ignore-submodules=all"]);
        if let Some(oid) = revision { args.push(oid); }
        args.push("--");
        metadata(self.repo, &args, |reader| {
            let mut fields = reader.split(0);
            while let Some(header) = fields.next() {
                let header = header?;
                let name = fields.next().context("missing Git path")??;
                let header = str::from_utf8(&header)?;
                let parts: Vec<_> = header.split_whitespace().collect();
                ensure!(parts.len() == 5 && parts[0].starts_with(':'), "invalid Git change header");
                ensure!(parts[4] != "U", "unmerged Git index");
                if !matches!(parts[1], "100644" | "100755") { continue; }
                let oid = parts[3];
                ensure!(is_oid(oid), "invalid blob ID");
                let path = str::from_utf8(&name).context("Git path is not UTF-8")?;
                if !self.seen.insert((oid.to_owned(), path.to_owned())) { continue; }
                let loc = Location { source: self.source, path, revision, blob: Some(oid) };
                self.objects.scan(oid, loc, self.audit)?;
            }
            Ok(())
        })
    }
}

pub fn scan<W: Write>(repo: &Path, staged: bool, audit: &mut Audit<W>) -> Result<()> {
    let label = repo.canonicalize()?.to_string_lossy().into_owned();
    let mut history = History { repo, source: &label, objects: Objects::open(repo)?, seen: HashSet::new(), audit };
    if staged { return history.changes(None); }
    metadata(repo, &["rev-parse", "--is-shallow-repository"], |mut reader| {
        let mut answer = String::new();
        reader.read_line(&mut answer)?;
        ensure!(answer.trim() == "false", "history requires a full local clone");
        Ok(())
    })?;
    metadata(repo, &["rev-list", "--reverse", "--topo-order", "--all"], |reader| {
        for line in reader.lines() {
            let oid = line?;
            ensure!(is_oid(&oid), "invalid commit ID");
            history.changes(Some(&oid))?;
        }
        Ok(())
    })
}
