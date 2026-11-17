"""构建 WordPress 安装包；只打包明确允许的插件文件。"""
from pathlib import Path
import hashlib
import re
import zipfile

root = Path(__file__).resolve().parents[1]
version = re.search(r"Version:\s*([\d.]+)", (root / "lumeshield.php").read_text(encoding="utf-8")).group(1)
out = root / "dist"
out.mkdir(exist_ok=True)
target = out / f"lumeshield-wordpress-{version}.zip"
files = [p for p in root.iterdir() if p.is_file() and (p.suffix in (".php", ".md", ".txt") or p.name == "LICENSE")]
for directory in ("assets", "includes", "templates"):
    files.extend(p for p in (root / directory).rglob("*") if p.is_file())

with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(files):
        # 固定归档时间与权限，使相同源码得到相同 ZIP。
        entry = zipfile.ZipInfo("lumeshield/" + path.relative_to(root).as_posix(), (2026, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, path.read_bytes())
with zipfile.ZipFile(target) as archive:
    assert archive.testzip() is None
    assert "lumeshield/lumeshield.php" in archive.namelist()
digest = hashlib.sha256(target.read_bytes()).hexdigest()
(out / "SHA256SUMS.txt").write_text(digest + "  " + target.name + "\n", encoding="utf-8")
print(f"{target.name}: {target.stat().st_size} bytes; SHA256 {digest}")
