#!/usr/bin/env python3
"""Standard-library archive consumer; never runs installer scripts or archive code.

Call only through an independently admitted driver. Failed staging is retained.
"""
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys
import tarfile
import unicodedata
import zipfile
import bz2
import lzma
import struct
import zlib

MAX_FILES = 100000
MAX_TOTAL = 6 * 1024**3
with open(pathlib.Path(__file__).with_name("archive-budget.json"), "rb") as policy_stream:
    policy_bytes = policy_stream.read(4097)
if len(policy_bytes) > 4096:
    raise ValueError("archive policy byte budget")
DEFAULT_LIMITS = json.loads(policy_bytes)
if set(DEFAULT_LIMITS) != {"compressed", "decoded", "members", "records", "metadata", "member_metadata", "name", "member", "expanded", "pax_keys", "extension_chain"} or any(type(value) is not int or value <= 0 for value in DEFAULT_LIMITS.values()):
    raise ValueError("invalid frozen archive policy")
CHUNK = 65536


def limits_for(override=None):
    result = dict(DEFAULT_LIMITS)
    if override:
        require(set(override) <= set(result), "unknown archive budget")
        for key, value in override.items():
            require(type(value) is int and 0 < value <= result[key], "invalid archive budget")
            result[key] = value
    return result


class PinnedReader:
    """The same stable descriptor is scanned and consumed; changes fail before reads."""
    def __init__(self, raw, path, expected_sha, expected_bytes, limits):
        self.raw, self.name, self.limits = raw, str(path), limits
        self.before = os.fstat(raw.fileno())
        require(stat.S_ISREG(self.before.st_mode) and 0 < expected_bytes <= limits["compressed"], "compressed archive budget")
        require(self.before.st_size == expected_bytes, "archive length mismatch")
        h = hashlib.sha256()
        while True:
            block = self.read(CHUNK)
            if not block:
                break
            h.update(block)
        require(h.hexdigest() == expected_sha, "archive digest mismatch")
        self.seek(0)

    def stable(self):
        current = os.fstat(self.raw.fileno())
        for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode"):
            require(getattr(current, key) == getattr(self.before, key), "archive changed during parsing")

    def read(self, count=-1):
        self.stable()
        if count < 0:
            count = self.before.st_size - self.tell()
        require(count <= max(CHUNK, self.limits["metadata"]), "raw parser read budget")
        data = self.raw.read(count)
        self.stable()
        return data

    def seek(self, offset, whence=0):
        self.stable()
        return self.raw.seek(offset, whence)

    def tell(self):
        return self.raw.tell()

    def seekable(self):
        return True


def decoded_chunks(raw, limits):
    raw.seek(0)
    magic = raw.read(6)
    raw.seek(0)
    kind = "gz" if magic.startswith(b"\x1f\x8b") else "xz" if magic == b"\xfd7zXZ\x00" else "bz2" if magic.startswith(b"BZh") else "tar"
    decoder = (zlib.decompressobj(31) if kind == "gz" else
               lzma.LZMADecompressor(memlimit=128 * 1024**2) if kind == "xz" else
               bz2.BZ2Decompressor() if kind == "bz2" else None)
    total = 0
    while True:
        block = raw.read(CHUNK)
        if not block:
            break
        if decoder is None:
            total += len(block)
            require(total <= limits["decoded"], "decompressed parser byte budget")
            yield block
            continue
        pending = block
        while pending or (kind != "gz" and not decoder.needs_input and not decoder.eof):
            output = decoder.decompress(pending, CHUNK)
            pending = decoder.unconsumed_tail if kind == "gz" else b""
            total += len(output)
            require(total <= limits["decoded"], "decompressed parser byte budget")
            if output:
                yield output
            if decoder.eof:
                tail = decoder.unused_data
                while True:
                    extra = raw.read(CHUNK)
                    if not extra:
                        break
                    require(kind == "xz" and not any(extra), "trailing compressed stream")
                    tail += extra
                    require(len(tail) <= 65536, "compressed padding budget")
                require(kind == "xz" and not any(tail) and len(tail) % 4 == 0 or not tail, "trailing compressed stream")
                return
    require(decoder is None or decoder.eof, "truncated compressed stream")


class DecodedReader:
    def __init__(self, raw, limits):
        self.chunks, self.buffer = iter(decoded_chunks(raw, limits)), bytearray()

    def read(self, count):
        require(0 <= count <= 1024 * 1024, "decoded read allocation budget")
        while len(self.buffer) < count:
            try:
                self.buffer.extend(next(self.chunks))
            except StopIteration:
                break
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def discard(self, count):
        while count:
            part = self.read(min(count, CHUNK))
            require(part, "truncated TAR body")
            count -= len(part)


def tar_number(field):
    if field[0] & 0x80:
        require(field[0] == 0x80, "negative or invalid TAR number")
        return int.from_bytes(bytes([0]) + field[1:], "big")
    value = field.rstrip(b"\x00 ").lstrip(b" ")
    require(not value or all(c in b"01234567" for c in value), "invalid TAR number")
    return int(value or b"0", 8)


def pax_fields(data, limits):
    result, offset = {}, 0
    while offset < len(data):
        space = data.find(b" ", offset, min(offset + 22, len(data)))
        require(space > offset and data[offset:space].isdigit(), "invalid bounded PAX length")
        length = int(data[offset:space])
        require(length > space - offset + 2 and offset + length <= len(data), "invalid PAX record")
        record = data[space + 1:offset + length]
        require(record.endswith(b"\n") and b"=" in record, "invalid PAX field")
        key, value = record[:-1].split(b"=", 1)
        require(0 < len(key) <= 256 and len(value) <= 16384, "PAX field metadata budget")
        require(not key.startswith(b"GNU.sparse"), "sparse TAR is outside the admitted formats")
        if key in (b"path", b"linkpath"):
            require(len(value) <= limits["name"], "archive name budget")
        if key == b"size":
            require(value.isdigit() and len(value) <= 20 and int(value) <= limits["member"], "PAX expanded-size budget")
        result[key] = value
        require(len(result) <= limits["pax_keys"], "PAX field-count budget")
        offset += length
    return result


def preflight_tar(raw, limits):
    stream, metadata, count, records, total, chain = DecodedReader(raw, limits), 0, 0, 0, 0, 0
    global_pax, local_pax = {}, {}
    while True:
        header = stream.read(512)
        require(len(header) == 512, "truncated TAR header")
        if not any(header):
            require(stream.read(512) == bytes(512), "TAR requires two end blocks")
            while True:
                tail = stream.read(CHUNK)
                if not tail:
                    break
                require(not any(tail), "nonzero trailing TAR bytes")
            require(count > 0, "empty TAR inventory")
            raw.seek(0)
            return {"members": count, "metadataBytes": metadata, "records": records}
        records += 1
        require(records <= limits["records"], "TAR record-count budget")
        metadata += 512
        require(metadata <= limits["metadata"], "TAR metadata budget")
        checksum = tar_number(header[148:156])
        require(sum(header[:148]) + 8 * 32 + sum(header[156:]) == checksum, "TAR checksum")
        require(len(header[:100].split(b"\x00", 1)[0]) + len(header[345:500].split(b"\x00", 1)[0]) <= limits["name"], "archive name budget")
        size, kind = tar_number(header[124:136]), header[156:157]
        if kind in (b"x", b"g", b"L", b"K"):
            chain += 1
            require(chain <= limits["extension_chain"], "TAR extension-chain budget")
            require(size <= limits["member_metadata"], "TAR individual metadata budget")
            require(kind not in (b"L", b"K") or size <= limits["name"] + 1, "archive name budget")
            padded = (size + 511) // 512 * 512
            metadata += padded
            require(metadata <= limits["metadata"], "TAR metadata budget")
            data = stream.read(size)
            require(len(data) == size, "truncated TAR metadata")
            stream.discard(padded - size)
            if kind in (b"x", b"g"):
                fields = pax_fields(data, limits)
                (global_pax if kind == b"g" else local_pax).update(fields)
                require(len(global_pax) + len(local_pax) <= limits["pax_keys"], "PAX cumulative field-count budget")
            continue
        chain = 0
        count += 1
        require(count <= limits["members"], "archive member-count budget")
        require(kind in (b"0", b"\x00", b"5"), "link or special TAR member")
        require(kind != b"5" or size == 0, "directory TAR payload")
        effective = {**global_pax, **local_pax}
        if b"size" in effective:
            size = int(effective[b"size"])
        require(kind != b"5" or size == 0, "PAX directory payload")
        local_pax = {}
        require(size <= limits["member"], "archive member-size budget")
        total += size
        require(total <= limits["expanded"], "archive expanded-size budget")
        stream.discard((size + 511) // 512 * 512)


def at(raw, offset, count):
    require(offset >= 0 and count >= 0 and offset + count <= raw.before.st_size, "ZIP offset outside input")
    raw.seek(offset)
    data = raw.read(count)
    require(len(data) == count, "truncated ZIP metadata")
    return data


def preflight_zip(raw, limits):
    size = raw.before.st_size
    tail = at(raw, max(0, size - 65557), min(size, 65557))
    end = tail.rfind(b"PK\x05\x06")
    require(end >= 0 and end + 22 <= len(tail), "ZIP end record absent")
    values = struct.unpack_from("<4s4H2LH", tail, end)
    _, disk, central_disk, disk_count, count, central_size, offset, comment = values
    require(end + 22 + comment == len(tail) and disk == central_disk == 0 and disk_count == count, "ZIP multidisk or trailing input")
    end_offset = size - len(tail) + end
    trailer = 22 + comment
    has_zip64_locator = end_offset >= 20 and at(raw, end_offset - 20, 4) == b"PK\x06\x07"
    if central_size == 0xffffffff or offset == 0xffffffff or count == 65535 and has_zip64_locator:
        locator = at(raw, end_offset - 20, 20)
        signature, disk, zip64_offset, disks = struct.unpack("<4sLQL", locator)
        require(signature == b"PK\x06\x07" and disk == 0 and disks == 1, "invalid ZIP64 locator")
        record = struct.unpack("<4sQ2H2L4Q", at(raw, zip64_offset, 56))
        require(record[0] == b"PK\x06\x06" and 44 <= record[1] <= limits["member_metadata"], "ZIP64 metadata budget")
        require(record[4] == record[5] == 0 and record[6] == record[7], "ZIP64 multidisk")
        count, central_size, offset = record[7], record[8], record[9]
        require(zip64_offset + record[1] + 12 == end_offset - 20, "ZIP64 record bounds")
        trailer += record[1] + 12 + 20
    require(0 < count <= limits["members"], "archive member-count budget")
    require(central_size + trailer <= limits["metadata"] and offset + central_size <= end_offset, "ZIP central metadata budget")
    cursor, metadata, expanded, compressed, ranges = offset, trailer, 0, 0, []
    for _ in range(count):
        fixed = at(raw, cursor, 46)
        require(fixed[:4] == b"PK\x01\x02", "invalid ZIP central record")
        flags, method = struct.unpack_from("<2H", fixed, 8)
        packed, unpacked = struct.unpack_from("<2L", fixed, 20)
        name_len, extra_len, comment_len, disk = struct.unpack_from("<4H", fixed, 28)
        local_offset = struct.unpack_from("<L", fixed, 42)[0]
        require(disk in (0, 65535) and not flags & 1 and method in (0, 8), "unsupported ZIP encryption/compression")
        require(0 < name_len <= limits["name"], "archive name budget")
        require(name_len + extra_len + comment_len <= limits["member_metadata"], "ZIP individual metadata budget")
        metadata += 46 + name_len + extra_len + comment_len
        require(metadata <= limits["metadata"], "ZIP metadata budget")
        variable = at(raw, cursor + 46, name_len + extra_len + comment_len)
        extra, position = variable[name_len:name_len + extra_len], 0
        while position < len(extra):
            require(position + 4 <= len(extra), "truncated ZIP extra field")
            tag, length = struct.unpack_from("<2H", extra, position)
            position += 4
            require(position + length <= len(extra), "ZIP extra field bounds")
            if tag == 1:
                data, current = extra[position:position + length], 0
                values = [unpacked, packed, local_offset]
                for index in range(3):
                    if values[index] == 0xffffffff:
                        require(current + 8 <= len(data), "truncated ZIP64 field")
                        values[index] = struct.unpack_from("<Q", data, current)[0]
                        current += 8
                unpacked, packed, local_offset = values
            position += length
        require(unpacked <= limits["member"], "archive member-size budget")
        expanded += unpacked
        compressed += packed
        require(expanded <= limits["expanded"] and compressed <= limits["compressed"], "ZIP expanded/compressed body budget")
        local = at(raw, local_offset, 30)
        require(local[:4] == b"PK\x03\x04", "invalid ZIP local header")
        local_name, local_extra = struct.unpack_from("<2H", local, 26)
        require(local_name <= limits["name"] and local_name + local_extra <= limits["member_metadata"], "ZIP local metadata budget")
        metadata += 30 + local_name + local_extra
        require(metadata <= limits["metadata"], "ZIP metadata budget")
        body = local_offset + 30 + local_name + local_extra
        require(body + packed <= offset, "ZIP member overlaps central directory")
        ranges.append((local_offset, body + packed))
        cursor += 46 + name_len + extra_len + comment_len
    require(cursor == offset + central_size, "ZIP central inventory size mismatch")
    ranges.sort()
    require(all(ranges[i][0] >= ranges[i - 1][1] for i in range(1, len(ranges))), "overlapping ZIP members")
    raw.seek(0)
    return {"members": count, "metadataBytes": metadata}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative(name):
    require(isinstance(name, str) and 0 < len(name) < 2048, "invalid member name")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    require(name and "\\" not in name and ":" not in name, "unsafe path")
    for part in name.split("/"):
        require(part not in ("", ".", "..") and not part.endswith((".", " ")), "unsafe component")
        require(not any(ord(c) < 32 for c in part), "control character")
        stem = part.split(".")[0].upper()
        require(stem not in {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}, "reserved Windows name")
    return name


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def extract(archive, destination, expected_sha, expected_bytes, budget=None):
    require(archive.is_file() and not archive.is_symlink(), "archive must be regular")
    require(not destination.exists() and not destination.is_symlink(), "destination must be absent")
    is_zip = archive.name.endswith(".zip")
    limits = limits_for(budget)
    raw = os.fdopen(os.open(archive, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb")
    source = None
    try:
        pinned = PinnedReader(raw, archive, expected_sha, expected_bytes, limits)
        parser = preflight_zip(pinned, limits) if is_zip else preflight_tar(pinned, limits)
        source = zipfile.ZipFile(pinned) if is_zip else tarfile.open(fileobj=pinned, mode="r:*")
        members = source.infolist() if is_zip else source.getmembers()
        require(0 < len(members) <= limits["members"], "invalid archive inventory size")
        seen, prepared, total, files = set(), [], 0, set()
        for member in members:
            original = member.filename if is_zip else member.name
            if original in (".", "./"):
                require(member.is_dir() if is_zip else member.isdir(), "non-directory root member")
                continue
            name = relative(original)
            key = unicodedata.normalize("NFC", name).casefold()
            require(key not in seen, "duplicate or case-alias member")
            seen.add(key)
            directory = member.is_dir() if is_zip else member.isdir()
            mode = ((member.external_attr >> 16) & 0o177777) if is_zip else member.mode
            if is_zip:
                require(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "special ZIP member")
                require(not member.flag_bits & 1, "encrypted ZIP member")
                size = member.file_size
            else:
                require(member.isfile() or member.isdir(), "link or special TAR member")
                size = member.size
            require(not mode & 0o7000, "special permission bits")
            require(directory or 0 <= size <= limits["member"], "oversized member")
            total += 0 if directory else size
            require(total <= limits["expanded"], "archive expanded-size budget exceeded")
            if not directory:
                files.add(name)
            prepared.append((member, name, directory, mode & 0o777))
        for _, name, _, _ in prepared:
            require(not any(parent in files for parent in str(pathlib.PurePosixPath(name).parent).split("/") if parent != "."), "file/directory conflict")
            for parent in pathlib.PurePosixPath(name).parents:
                require(str(parent) not in files, "file/directory conflict")
        # All names, types, sizes and modes are inspected before the first extraction write.
        destination.mkdir(parents=False, exist_ok=False)
        for member, name, directory, mode in prepared:
            target = destination / name
            if directory:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source.open(member) if is_zip else source.extractfile(member)
                with stream, open(target, "xb") as output:
                    remaining = member.file_size if is_zip else member.size
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        require(chunk, "truncated member")
                        output.write(chunk)
                        remaining -= len(chunk)
                    require(not stream.read(1), "member exceeds declared length")
                # Writable bits in old Windows data archives are retained only as data;
                # executable permissions are restricted to the archived executable bit.
                target.chmod(0o755 if mode & 0o111 else 0o644)
        return {"members": len(members), "files": len(files), "expandedBytes": total, "sha256": expected_sha, "parser": parser}
    finally:
        if source is not None:
            source.close()
        raw.close()


def copy_regular(source, target):
    require(not source.is_symlink(), "tool component link")
    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        for child in sorted(source.iterdir()):
            copy_regular(child, target / child.name)
    else:
        require(source.is_file(), "special component")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            require(digest(target) == digest(source), "conflicting Rust component payload")
        else:
            with open(source, "rb") as inp, open(target, "xb") as out:
                shutil.copyfileobj(inp, out)
            target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def install_tools(directory, destination, platform):
    require(not destination.exists(), "prepared tools must be absent")
    destination.mkdir()
    rust = json.loads((directory / f"toolchain-{platform}-manifest.json").read_text())
    require(rust["version"] == "1.95.0" and rust["platform"] == platform and len(rust["components"]) == 4, "unexpected Rust manifest")
    prefix = destination / "rust"
    prefix.mkdir()
    unpacked = destination / "unpacked"
    unpacked.mkdir()
    for component in rust["components"]:
        name = relative(component["name"])
        require("/" not in name, "component root")
        target = unpacked / name
        extract(directory / relative(component["filename"]), target, component["sha256"], component["size"])
        root = target / name
        for subcomponent in (root / "components").read_text().splitlines():
            subcomponent = relative(subcomponent)
            for line in (root / subcomponent / "manifest.in").read_text().splitlines():
                kind, path = line.split(":", 1)
                require(kind in ("dir", "file"), "installer manifest kind")
                path = relative(path)
                copy_regular(root / subcomponent / path, prefix / path)
    tools = json.loads((directory / f"build-tools-{platform}-manifest.json").read_text())
    require(tools["host"] == platform and len(tools["tools"]) == 2, "unexpected WASM tool manifest")
    tool_bin = destination / "bin"
    tool_bin.mkdir()
    suffix = ".exe" if platform == "windows-x64" else ""
    for item in tools["tools"]:
        require(item["tool"] in ("trunk", "wasm-bindgen"), "unknown WASM helper")
        require(item["tag"] == ("v0.22.1" if item["tool"] == "trunk" else "0.2.129"), "WASM tool version")
        target = unpacked / item["tool"]
        extract(directory / relative(item["name"]), target, item["sha256"], item["size"])
        root = target if item["tool"] == "trunk" else target / item["name"][:-7]
        for binary in (["trunk"] if item["tool"] == "trunk" else ["wasm-bindgen", "wasm-bindgen-test-runner", "wasm2es6js"]):
            copy_regular(root / (binary + suffix), tool_bin / (binary + suffix))
    opt = json.loads((directory / f"wasm-opt-{platform}-manifest.json").read_text())
    require(opt["platform"] == platform and opt["version"] == "version_131", "Binaryen version")
    target = unpacked / "binaryen"
    extract(directory / relative(opt["name"]), target, opt["sha256"], opt["size"])
    root = target / "binaryen-version_131"
    copy_regular(root / "bin" / ("wasm-opt" + suffix), tool_bin / ("wasm-opt" + suffix))
    if (root / "lib").exists():
        copy_regular(root / "lib", destination / "lib")
    return {"rust": str(prefix), "bin": str(tool_bin), "installerScriptsExecuted": False}


def pack(directory, archive):
    require(directory.is_dir() and not directory.is_symlink() and not archive.exists(), "invalid package paths")
    paths, total = [], 0
    for path in directory.rglob("*"):
        require(len(paths) < MAX_FILES, "package member-count budget")
        relative(path.relative_to(directory).as_posix())
        require(not path.is_symlink() and (path.is_file() or path.is_dir()), "special package member")
        if path.is_file():
            size = path.stat().st_size
            require(size <= DEFAULT_LIMITS["member"], "package member-size budget")
            total += size
            require(total <= MAX_TOTAL, "package expanded-size budget")
        paths.append(path)
    paths.sort()
    require(paths, "empty package inventory")
    with open(archive, "xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as out:
        for path in paths:
            if path.is_file():
                info = out.gettarinfo(str(path), directory.name + "/" + path.relative_to(directory).as_posix())
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                with open(path, "rb") as stream:
                    out.addfile(info, stream)
    return {"name": archive.name, "bytes": archive.stat().st_size, "sha256": digest(archive), "files": sum(p.is_file() for p in paths)}


def main():
    command = sys.argv[1]
    if command == "extract":
        result = extract(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), sys.argv[4], int(sys.argv[5]))
    elif command == "install-tools":
        result = install_tools(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), sys.argv[4])
    elif command == "pack":
        result = pack(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
    else:
        raise ValueError("unknown archive stage")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
