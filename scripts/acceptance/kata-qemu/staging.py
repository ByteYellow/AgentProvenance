"""Optional, pinned executable staging in the owned Guest's private tmpfs."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time

from common import command, digest, require


def trusted_source(source):
    for path in (source, *source.parents):
        info = path.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
                "executable staging requires trusted source ancestors")


def copy_pinned(source, destination, expected):
    """Never execute partially copied, changed, oversized or symlink inputs."""
    source, destination = Path(source), Path(destination)
    trusted_source(source)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    created = False
    try:
        with os.fdopen(fd, "rb") as reader:
            info = os.fstat(reader.fileno())
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 256 << 20, "invalid staging executable size/type")
            size, sha = 0, hashlib.sha256()
            with destination.open("xb") as writer:
                created = True
                os.chmod(destination, 0o400)
                while chunk := reader.read(4 << 20):
                    size += len(chunk)
                    require(size <= info.st_size, "staging input grew during copy")
                    sha.update(chunk)
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            require(size == info.st_size and sha.hexdigest() == expected and digest(destination) == expected,
                    "staged executable differs from version lock")
            destination.chmod(0o500)
            return {"source": str(source), "path": str(destination), "sha256": expected, "bytes": size}
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


class GuestBinaries:
    def __init__(self, args, lock, receipt, report):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        require(os.geteuid() == 0 and boot == receipt["identity"]["guest_boot_id"] and
                boot != receipt["control_plane"]["node_boot_id"] and
                os.environ.get("AP_POD_UID") == receipt["identity"]["pod_uid"],
                "refuse executable staging outside the bound Guest")
        for path in (Path("/run"), Path("/")):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    "Guest staging parent must be trusted")
        self.path = Path(tempfile.mkdtemp(prefix="agentprov-executables-", dir="/run"))
        self.mounted = False
        observed = {"guest_boot_id": boot, "filesystem": "tmpfs", "limit_mib": 384, "executables": []}
        report["executable_staging"] = observed
        start = time.monotonic()
        try:
            command(["mount", "-t", "tmpfs", "-o", "size=384m,nosuid,nodev,mode=0700", "tmpfs", self.path], timeout=10)
            self.mounted = True
            for key, pin, name in (("binary", "sensor", "agentprov"), ("verifier", "verifier", "agentprov-verify")):
                source = getattr(args, key, None)
                if source:
                    target = self.path / name
                    observed["executables"].append(copy_pinned(source, target, lock[pin]["sha256"]))
                    setattr(args, key, target)
            observed["elapsed_seconds"] = time.monotonic() - start
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.mounted:
            command(["umount", self.path], timeout=10)
            self.mounted = False
        self.path.rmdir()
