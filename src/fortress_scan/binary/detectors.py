"""Các detector: biến cấu trúc + chuỗi của một tệp thành danh sách dấu hiệu.

Nguyên tắc chung:

* Mỗi dấu hiệu kèm bằng chứng cụ thể ( tên import, chuỗi, offset ) để người
  đọc tự kiểm chứng, không bắt tin vào một con số.
* Năng lực phổ biến ( duyệt tệp, mã hoá ) đứng một mình chỉ là bối cảnh. Chỉ
  khi chúng hội đủ thành chuỗi mới thành dấu hiệu đáng ngờ.
* Ngưỡng của các danh sách ( đuôi tệp, tên dịch vụ ) đặt đủ cao để phần mềm
  lành phổ biến không chạm tới; README ghi rõ con số đo trên bộ tệp lành.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .catalogue import spec
from .model import Evidence, IndicatorHit, Ioc, Parsed, Tier
from .strings import StringPool

MAX_EVIDENCE = 8


def _location(pool: StringPool, position: int) -> str:
    offset, label = pool.locate(position)
    source = label.rsplit(":", 1)[0] if ":" in label else ""
    if offset < 0:
        where = "dòng %d" % (-offset)
    else:
        where = "offset 0x%x" % offset
    return "%s ( %s )" % (where, source) if source and source not in ("ascii", "utf16") else where


def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    piece = text[left:right].replace("\n", " | ")
    return ("..." if left else "") + piece.strip() + ("..." if right < len(text) else "")


# ============================================================ khớp năng lực


@dataclass(frozen=True)
class Capability:
    key: str
    apis: Tuple[str, ...] = ()
    idents: Tuple[str, ...] = ()
    patterns: Tuple[str, ...] = ()


def _api_key(name: str) -> List[str]:
    """Tên chuẩn hoá để so: chữ thường, bỏ hậu tố A/W của Win32, bỏ phiên bản ELF."""
    name = name.split("@", 1)[0]
    lowered = name.lower()
    keys = [lowered]
    if len(name) > 3 and name[-1] in "AW" and name[-2].islower():
        keys.append(lowered[:-1])
    return keys


CAPABILITIES: Tuple[Capability, ...] = (
    Capability(
        "enumerate",
        apis=(
            "findfirstfile", "findfirstfileex", "findnextfile", "getlogicaldrives",
            "getlogicaldrivestrings", "findfirstvolume", "findnextvolume", "opendir",
            "fdopendir", "readdir", "readdir64", "nftw", "nftw64", "fts_open", "fts_read", "scandir",
        ),
        idents=(
            "GetFiles", "EnumerateFiles", "GetDirectories", "EnumerateDirectories",
            "EnumerateFileSystemEntries", "GetFileSystemEntries", "GetLogicalDrives",
            "listFiles", "walkFileTree", "walk", "scandir", "rglob", "listdir",
        ),
        patterns=(
            r"path/filepath\.walk(?:dir)?\b", r"\bos\.readdir\b", r"io/fs\.walkdir",
            r"java/nio/file/files\b", r"get-childitem[^\n]{0,80}-recurse", r"\bgci\b[^\n]{0,40}-r(?:ecurse)?\b",
            r"\bfind\s+[/~$.][^\n]{0,80}-type\s+f", r"\.getfolder\(", r"\.subfolders\b",
            r"\bfor\s+/r\s", r"\bdir\s+/s\b", r"std::fs::read_dir", r"walkdir::",
        ),
    ),
    Capability(
        "symmetric",
        apis=(
            "cryptencrypt", "cryptderivekey", "bcryptencrypt", "bcryptgeneratesymmetrickey",
            "evp_encryptinit", "evp_encryptinit_ex", "evp_encryptupdate", "evp_encryptfinal_ex",
            "evp_cipherinit_ex", "aes_set_encrypt_key", "aes_cbc_encrypt", "crypto_secretbox_easy",
            "crypto_stream_xchacha20_xor", "crypto_aead_chacha20poly1305_ietf_encrypt",
            "crypto_aead_xchacha20poly1305_ietf_encrypt", "mbedtls_aes_setkey_enc",
            "mbedtls_aes_crypt_cbc", "mbedtls_gcm_crypt_and_tag", "cccrypt", "cccryptorcreate",
        ),
        idents=(
            "RijndaelManaged", "AesManaged", "AesCryptoServiceProvider", "AesCng", "CreateEncryptor",
            "CryptoStream", "TripleDESCryptoServiceProvider", "AesGcm", "Fernet", "AESGCM",
        ),
        patterns=(
            r"crypto/aes\.newcipher", r"crypto/cipher\.new(?:gcm|cbcencrypter|ctr|cfbencrypter)",
            r"golang\.org/x/crypto/(?:chacha20|salsa20)", r"javax/crypto/cipher",
            r"javax/crypto/spec/secretkeyspec", r"\bcrypto\.cipher\b",
            r"cryptography\.hazmat\.primitives\.ciphers", r"cryptography\.fernet",
            r"\bopenssl\s+(?:enc\b|aes-\d+)", r"\bgpg\b[^\n]{0,40}(?:\s-c\b|--symmetric|--encrypt)",
            r"system\.security\.cryptography\.(?:aes|rijndael)", r"\.createencryptor\(",
            r"\baes_gcm::|\bchacha20poly1305::",
        ),
    ),
    Capability(
        "asymmetric",
        apis=(
            "cryptimportkey", "cryptimportpublickeyinfo", "cryptimportpublickeyinfoex2",
            "bcryptimportkeypair", "cryptgenkey", "cryptexportkey", "rsa_public_encrypt",
            "evp_pkey_encrypt", "pem_read_bio_rsa_pubkey", "pem_read_bio_pubkey",
            "crypto_box_seal", "crypto_box_easy", "mbedtls_rsa_pkcs1_encrypt", "mbedtls_pk_encrypt",
            "seckeycreateencrypteddata",
        ),
        idents=(
            "RSACryptoServiceProvider", "RSACng", "ImportParameters", "FromXmlString",
            "ImportRSAPublicKey", "ImportSubjectPublicKeyInfo", "PKCS1_OAEP",
        ),
        patterns=(
            r"crypto/rsa\.encrypt(?:oaep|pkcs1v15)", r"golang\.org/x/crypto/curve25519",
            r"rsa/ecb/(?:oaep|pkcs1)", r"\bpkcs1_oaep\b", r"asymmetric\.(?:rsa|padding)",
        ),
    ),
    Capability(
        "destructive-write",
        apis=(
            "movefile", "movefileex", "movefilewithprogress", "replacefile", "rename",
            "renameat", "renameat2", "unlinkat",
        ),
        idents=("MoveTo", "WriteAllBytes", "OpenWrite", "renameTo", "rename", "replace", "unlink"),
        patterns=(
            r"\bos\.rename\b", r"\bos\.remove\b", r"\brename-item\b", r"\bremove-item\b",
            r"\bset-content\b", r"writeallbytes", r"\bout-file\b", r"\brm\s+-[a-z]*[rf]",
            r"\bmv\s+\S", r"\.movefile\b", r"\.deletefile\b", r"java/io/file\b",
        ),
    ),
    Capability(
        "service-stop",
        apis=(
            "openscmanager", "enumservicesstatusex", "controlservice", "changeserviceconfig",
            "createtoolhelp32snapshot", "process32next", "terminateprocess",
        ),
        patterns=(
            r"\bnet1?(?:\.exe)?\s+stop\s", r"\bsc(?:\.exe)?\s+(?:stop|config)\s", r"\btaskkill\b",
            r"\bstop-service\b", r"\bstop-process\b", r"\bsystemctl\s+stop\b", r"\bkillall\b", r"\bpkill\b",
        ),
    ),
    Capability(
        "restart-manager",
        apis=("rmgetlist", "rmshutdown", "rmregisterresources"),
    ),
    Capability(
        "shares",
        apis=("wnetopenenum", "wnetenumresource", "netshareenum", "netserverenum"),
        patterns=(r"\\\\[^\\\n]{1,64}\\(?:admin|[c-f]|ipc)\$",),
    ),
    Capability(
        "wallpaper",
        apis=("systemparametersinfo",),
    ),
)

_CAPABILITY_REGEX: Dict[str, Optional["re.Pattern[str]"]] = {
    cap.key: re.compile("|".join("(?:%s)" % p for p in cap.patterns)) if cap.patterns else None
    for cap in CAPABILITIES
}
# Không đặt lookbehind ở đầu mẫu: nó chặn tối ưu "tập ký tự đầu" của re và
# làm mẫu chậm hơn chục lần trên tệp lớn. Ranh giới trái được kiểm bằng tay.
_API_WORDS: Dict[str, Optional["re.Pattern[str]"]] = {
    cap.key: re.compile(r"(?:%s)(?:a|w)?(?![a-z0-9_])" % "|".join(cap.apis)) if cap.apis else None
    for cap in CAPABILITIES
}


def _word_start(text: str, position: int) -> bool:
    if position == 0:
        return True
    previous = text[position - 1]
    return not (previous.isalnum() or previous == "_")


@dataclass
class Capabilities:
    found: Dict[str, List[Evidence]]

    def has(self, key: str) -> bool:
        return bool(self.found.get(key))

    def evidence(self, key: str) -> List[Evidence]:
        return self.found.get(key, [])


def match_capabilities(parsed: Parsed, pool: StringPool) -> Capabilities:
    found: Dict[str, List[Evidence]] = {}
    import_index: Dict[str, List[str]] = {}
    for item in parsed.imports:
        if not item.name:
            continue
        label = "%s!%s" % (item.library, item.name) if item.library else item.name
        for key in _api_key(item.name):
            import_index.setdefault(key, []).append(label)
    ident_index: Dict[str, str] = {}
    for name, source in parsed.names:
        ident_index.setdefault(name, source)
        if source == "symtab":
            for key in _api_key(name):
                import_index.setdefault(key, []).append("%s ( symtab )" % name)
    lower = pool.lower
    for cap in CAPABILITIES:
        evidence: List[Evidence] = []
        seen: Set[str] = set()
        for api in cap.apis:
            for label in import_index.get(api, ()):
                if label not in seen:
                    seen.add(label)
                    evidence.append(Evidence(label, "import"))
        for ident in cap.idents:
            if ident in ident_index and ident not in seen:
                seen.add(ident)
                evidence.append(Evidence(ident, ident_index[ident]))
        word = _API_WORDS[cap.key]
        if word is not None and len(evidence) < MAX_EVIDENCE:
            for match in word.finditer(lower):
                token = match.group()
                if token in seen or token in import_index or not _word_start(lower, match.start()):
                    continue
                seen.add(token)
                evidence.append(
                    Evidence(pool.text[match.start() : match.end()], "chuỗi tại " + _location(pool, match.start()))
                )
                if len(evidence) >= MAX_EVIDENCE:
                    break
        regex = _CAPABILITY_REGEX[cap.key]
        if regex is not None and len(evidence) < MAX_EVIDENCE:
            for match in regex.finditer(lower):
                token = match.group().strip()
                if token in seen:
                    continue
                seen.add(token)
                evidence.append(
                    Evidence(_snippet(pool.text, match.start(), match.end(), 30), _location(pool, match.start()))
                )
                if len(evidence) >= MAX_EVIDENCE:
                    break
        if evidence:
            found[cap.key] = evidence[:MAX_EVIDENCE]
    return Capabilities(found)


# ============================================================ mẫu lệnh / chuỗi


def _rx(*patterns: str) -> "re.Pattern[str]":
    return re.compile("|".join("(?:%s)" % p for p in patterns))


RECOVERY_INHIBITION = _rx(
    r"vssadmin(?:\.exe)?\W{1,6}delete\W{1,6}shadows",
    r"vssadmin(?:\.exe)?\W{1,6}resize\W{1,6}shadowstorage",
    r"wmic(?:\.exe)?\W{1,6}shadowcopy\W{1,6}delete",
    r"win32_shadowcopy[^\n]{0,120}(?:\.delete\(|remove-(?:wmi|cim)instance|delete\(\))",
    r"get-(?:wmi|cim)object\W{1,6}win32_shadowcopy",
    r"bcdedit(?:\.exe)?[^\n]{0,60}recoveryenabled\W{1,6}(?:no|off|false)",
    r"bcdedit(?:\.exe)?[^\n]{0,60}bootstatuspolicy\W{1,6}ignoreallfailures",
    r"wbadmin(?:\.exe)?\W{1,6}delete\W{1,6}(?:catalog|systemstatebackup|backup)",
    r"diskshadow[^\n]{0,40}delete\W{1,6}shadows",
    r"vim-cmd\W{1,6}vmsvc/snapshot\.removeall",
    r"esxcli[^\n]{0,60}snapshot[^\n]{0,20}(?:remove|delete)",
    r"tmutil\W{1,6}(?:deletelocalsnapshots|disable)\b",
    r"reagentc(?:\.exe)?\W{1,6}/disable",
)

LOG_CLEARING = _rx(
    r"wevtutil(?:\.exe)?\W{1,6}(?:cl|clear-log)\W",
    r"\bclear-eventlog\b",
    r"\bremove-eventlog\b",
    r"fsutil(?:\.exe)?\W{1,6}usn\W{1,6}deletejournal",
    r"\bhistory\s+-c\b",
    r"\bunset\s+histfile\b",
    r"(?:\brm\s+-[a-z]*f[a-z]*\s+|>\s*)/var/log/",
)

DEFENSE_EVASION = _rx(
    r"set-mppreference[^\n]{0,80}-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|blockatfirstseen)",
    r"\bdisableantispyware\b",
    r"\bdisablerealtimemonitoring\b",
    r"add-mppreference\W{1,6}-exclusion(?:path|process|extension)",
    r"(?:net1?|sc)(?:\.exe)?\s+(?:stop|config)\s+windefend",
    r"netsh(?:\.exe)?\s+advfirewall\s+set\s+\S+\s+state\s+off",
    r"bcdedit(?:\.exe)?[^\n]{0,40}\bsafeboot\b",
)

SELF_DELETE = _rx(
    r"cmd(?:\.exe)?\W{1,4}/c\W[^\n]{0,80}(?:ping\s+(?:127\.0\.0\.1|localhost|-n)|timeout\s+/t|choice\s+/[ctdn])[^\n]{0,80}\bdel\b",
    r"\bdel\s+(?:/[fq]\s+){0,3}\"?%~?f?0\b",
    r"remove-item\s+[^\n]{0,30}(?:\$myinvocation|\$pscommandpath)",
    r"\brm\s+-[a-z]*f[a-z]*\s+\"?\$0\b",
    r"/c\s+del\s+/[fq]\b",
)

PERSISTENCE = _rx(
    r"software\\+microsoft\\+windows\\+currentversion\\+run(?:once)?\b",
    r"schtasks(?:\.exe)?\W{1,6}/create",
    r"\\start menu\\programs\\startup",
    r"winlogon\\+(?:userinit|shell)\b",
    r"register-scheduledtask|new-scheduledtask",
    r"/etc/(?:cron\.d|crontab)\b|\bcrontab\s+-[le]?",
    r"/etc/systemd/system/[^\s]{1,80}\.service|\bsystemctl\s+enable\b",
    r"library/launch(?:agents|daemons)",
)

SECURE_DELETE = _rx(
    r"cipher(?:\.exe)?\s+/w:",
    r"(?<![%\w])sdelete(?:64)?(?:\.exe)?\s+[-/][a-z]",
    r"(?<![%\w])shred\s+-[a-z]",
)

RAW_DISK = _rx(r"\\\\\.\\physicaldrive\d", r"\\\\\?\\globalroot\\device\\harddisk\d")

ESXI_PATHS = _rx(
    r"/vmfs/volumes",
    r"\besxcli\s+(?:vm\s+process|system|storage)",
    r"\bvim-cmd\s+vmsvc/(?:getallvms|power\.off|power\.shutdown)",
)
ESXI_FILES = re.compile(r"\.(vmdk|vmx|vmsn|vswp|vmem|vmsd|nvram|vmss)(?![a-z0-9])")

WALLPAPER_STRING = re.compile(r"control panel\\+desktop|\bwallpaper\b")


def _pattern_evidence(regex: "re.Pattern[str]", pool: StringPool, limit: int = MAX_EVIDENCE) -> List[Evidence]:
    evidence: List[Evidence] = []
    seen: Set[str] = set()
    for match in regex.finditer(pool.lower):
        token = match.group()
        if token in seen:
            continue
        seen.add(token)
        evidence.append(Evidence(_snippet(pool.text, match.start(), match.end(), 30), _location(pool, match.start())))
        if len(evidence) >= limit:
            break
    return evidence


# ---------------------------------------------------------- danh sách tên dịch vụ

# Tên dịch vụ / tiến trình xuất hiện trong danh sách "kill" của ransomware,
# theo các khuyến cáo #StopRansomware của CISA và báo cáo vendor. Chia nhóm để
# một trình cài đặt Office ( chỉ đóng Word, Excel ) không chạm ngưỡng.
KILL_TARGETS: Dict[str, Tuple[str, ...]] = {
    "database": (
        "sqlservr", "sqlwriter", "sqlagent", "sqlbrowser", "mssqlserver", "mysqld", "mysqld-nt",
        "mysqld-opt", "ocssd", "dbsnmp", "synctime", "agntsvc", "isqlplussvc", "xfssvccon",
        "ocautoupds", "encsvc", "dbeng50", "sqbcoreservice", "oracleservice", "mongod",
        "msexchangeis", "msexchangesa", "msexchangemta", "msexchangeadtopology",
    ),
    "backup": (
        "veeam", "veeamtransportsvc", "veeamdeploymentservice", "veeamnfssvc", "backupexecvssprovider",
        "backupexecagentaccelerator", "backupexecagentbrowser", "backupexecjobengine",
        "backupexecmanagementservice", "backupexecrpcservice", "acrsch2svc", "acronisagent",
        "casad2dwebsvc", "caarcupdatesvc", "yoobackup", "vsnapvss", "pdvfsservice", "gxvss", "gxblr",
        "gxfwd", "gxcvd", "gxcimgr", "bedbh", "stc_raw_agent", "memtas", "mepocs", "veeamagent",
    ),
    "security": (
        "defwatch", "ccevtmgr", "ccsetmgr", "savroam", "rtvscan", "savservice", "savadminservice",
        "sophossps", "sntp", "zhudongfangyu", "mbamservice", "ekrn", "avp", "msmpeng", "windefend",
        "mcshield", "sepmasterservice", "kavfs", "klnagent", "tmlisten", "ntrtscan",
    ),
    "office-mail": (
        "winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote", "infopath",
        "visio", "thebat", "thunderbird", "tbirdconfig", "mydesktopservice", "mydesktopqos", "ocomm",
        "wordpad", "steam", "firefoxconfig", "qbfcservice", "qbidpservice", "qbcfmonitorservice",
    ),
}
_KILL_LOOKUP: Dict[str, str] = {name: group for group, names in KILL_TARGETS.items() for name in names}
_KILL_REGEX = re.compile(
    r"(?<![a-z0-9_\-])(%s)(?:\.exe)?(?![a-z0-9_\-])" % "|".join(sorted(map(re.escape, _KILL_LOOKUP), key=len, reverse=True))
)

# ---------------------------------------------------------- danh sách đuôi tệp

TARGET_EXTENSIONS = frozenset(
    """doc docx docm dot dotx xls xlsx xlsm xlsb xlt ppt pptx pptm pps ppsx odt ods odp odg rtf pdf
    txt csv xml json md tex wpd wps msg eml pst ost mbox vcf sql mdb accdb db dbf sqlite sqlite3 db3
    frm myd myi ibd ndf mdf ldf bak backup bkf tib vbk vib vbm vrb old tmp sav jpg jpeg png gif bmp
    tif tiff psd ai svg raw cr2 nef dng mp3 wav flac mp4 avi mov mkv wmv 3gp zip rar 7z tar gz tgz
    bz2 iso vmdk vhd vhdx vmx vdi ova ovf qcow2 dwg dxf dwf step stp max 3ds blend c cpp h cs java
    py php js rb go sln vcxproj pem key crt pfx p12 kdbx wallet dat config ini cfg asp aspx jsp html
    htm cdr indd lay6 sxw stw sxc sxi sxd uot uop uos uof 602 hwp""".split()
)
_EXTENSION_ALONE = re.compile(r"^\*?\.([a-z0-9]{1,6})$")
_EXTENSION_LIST = re.compile(r"^(?:\*?\.?[a-z0-9]{1,6}[\s,;|]{1,3}){5,}\*?\.?[a-z0-9]{1,6}[\s,;|]?$")

SYSTEM_EXCLUSIONS = (
    "boot.ini", "bootmgr", "bootfont.bin", "ntldr", "ntuser.dat", "ntuser.ini", "iconcache.db",
    "thumbs.db", "desktop.ini", "autorun.inf", "bootsect.bak", "$recycle.bin",
    "system volume information", "$windows.~bt", "$windows.~ws", "msocache", "perflogs",
    "tor browser", "config.msi", "ntuser.dat.log", "autorun.ini", "boot",
)
_EXCLUSION_REGEX = re.compile(
    r"(?<![a-z0-9_])(%s)(?![a-z0-9_])" % "|".join(re.escape(item) for item in SYSTEM_EXCLUSIONS if item != "boot")
)

# ---------------------------------------------------------- ghi chú tống tiền

NOTE_PHRASES: Dict[str, "re.Pattern[str]"] = {
    "encrypted": re.compile(
        r"(?:files?|data|documents?|photos|databases?|network|servers?|computers?|everything)\W{1,3}(?:\w{1,15}\W{1,3}){0,4}"
        r"(?:have|has|had|were|was|are|is|got|been)\W{1,3}(?:\w{1,15}\W{1,3}){0,2}(?:encrypted|locked|crypted|encoded|ciphered)"
        r"|\b(?:encrypted|locked)\s+by\s+\w|\ball\s+(?:of\s+)?your\s+(?:important\s+)?(?:files|data|documents)\b"
    ),
    "decrypt": re.compile(
        r"\bdecrypt(?:ion|or|er)?\W{1,3}(?:\w{1,15}\W{1,3}){0,3}(?:tool|key|software|program|files?|price|service)"
        r"|(?:restore|recover|return|get\s+back|unlock)\W{1,3}(?:\w{1,15}\W{1,3}){0,3}(?:files|data|documents)\b"
        r"|\bprivate\s+key\b|\btest\s+decrypt"
    ),
    "payment": re.compile(
        r"\b(?:bitcoins?|btc|monero|xmr|ransom|pay\s+(?:us|the|for|in)|payment|purchase\s+(?:the\s+)?(?:key|decrypt))\b"
    ),
    "contact": re.compile(
        r"\btor\s+browser\b|torproject\.org|[a-z2-7]{16,56}\.onion\b|\bqtox\b|\btox\s+(?:id|chat)\b"
        r"|\bsession\s+(?:messenger|id)\b|\b(?:contact|write\s+to|email|e-mail)\s+us\b|\bjabber\b"
    ),
    "threat": re.compile(
        r"\b(?:do\s+not|don'?t|dont|never)\W{1,3}(?:\w{1,15}\W{1,3}){0,3}(?:rename|modify|delete|use\s+third|contact\s+(?:the\s+)?police|turn\s+off|reinstall|try\s+to\s+(?:decrypt|recover))"
        r"|will\s+be\s+(?:published|leaked|sold|deleted|lost)\b|price\s+(?:will|is\s+going\s+to)\s+(?:be\s+)?(?:double|increase|rise)"
        r"|\b(?:leak|blog)\s+(?:site|page)\b|\b\d{1,3}\s*(?:hours|days)\s+(?:to|before|after)\b|\bstolen\s+data\b"
    ),
    "identity": re.compile(r"\b(?:your|personal|unique)\s+(?:id|key|identifier|code)\b|\bvictim\s+id\b"),
}
NOTE_WINDOW = 3000
_VICTIM_ID = re.compile(r"(?:your|personal|unique|victim)\s+(?:id|key|identifier)\s*[:=]?\s*([a-z0-9+/=_\-]{8,128})", re.IGNORECASE)

NOTE_FILENAME = re.compile(
    r"(?<![a-z0-9])[!#_\-\[\]+ ]{0,8}"
    r"(?:how[_\- ]{0,2}to[_\- ]{0,2}(?:decrypt|restore|recover|unlock|back)\w{0,20}"
    r"|(?:decrypt|restore|recover|recovery|unlock)[_\- ]{0,2}(?:my|your|all)?[_\- ]{0,2}(?:files?|data|instructions?|info)\w{0,12}"
    r"|read[_\- ]{0,2}me[_\- ]{0,2}(?:now|first|for[_\- ]{0,2}decrypt|to[_\- ]{0,2}decrypt|!{1,4})"
    r"|ransom[_\- ]{0,2}note|_readme_)"
    r"[!#_\-\]+ ]{0,8}\.(?:txt|html?|hta|rtf|url|png|bmp|jpg)(?![a-z0-9])"
)

# ---------------------------------------------------------- địa chỉ, khoá

_ONION_V3 = re.compile(r"(?<![a-z2-7])([a-z2-7]{56})\.onion\b")
_ONION_V2 = re.compile(r"(?<![a-z2-7])([a-z2-7]{16})\.onion\b")
_BTC_BASE58 = re.compile(r"(?<![A-Za-z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
_BTC_BECH32 = re.compile(r"(?<![a-z0-9])(bc1[ac-hj-np-z02-9]{11,71})(?![a-z0-9])")
_MONERO = re.compile(r"(?<![A-Za-z0-9])(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})(?![A-Za-z0-9])")
_ANON_EMAIL = re.compile(
    r"[a-z0-9._%+\-]{2,64}@(?:protonmail\.(?:com|ch)|proton\.me|pm\.me|tutanota\.(?:com|de)|tuta\.io|tutamail\.com"
    r"|keemail\.me|onionmail\.(?:org|com)|cock\.li|airmail\.cc|firemail\.cc|mail2tor\.com|secmail\.pro"
    r"|dnmx\.org|msgsafe\.io|cyberfear\.com|elude\.in|420blaze\.it|torbox3uiot6wchz\.onion|mailfence\.com)\b"
)
# ID Tox / Session chỉ là một dãy hex, trùng với hằng số mật mã và số thập
# phân dài; nên chỉ nhận khi có từ khoá đứng ngay trước trong cùng chuỗi.
_TOX_ID = re.compile(r"\btox[^\n]{0,40}?(?<![0-9a-f])([0-9a-f]{76})(?![0-9a-f])")
_SESSION_ID = re.compile(r"\bsession[^\n]{0,40}?(?<![0-9a-f])(05[0-9a-f]{64})(?![0-9a-f])")

_PEM_PUBLIC = re.compile(r"-----begin (?:rsa )?public key-----")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

AES_SBOX_PREFIX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
AES_INV_SBOX_PREFIX = bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb")
CHACHA_SIGMA = (b"expand 32-byte k", b"expand 16-byte k")
_SPKI_RSA = bytes.fromhex("300d06092a864886f70d0101010500")
_CRYPTOAPI_PUBLICKEYBLOB = b"\x06\x02\x00\x00\x00\xa4\x00\x00RSA1"


def _base58check(address: str) -> bool:
    value = 0
    for char in address:
        index = _B58.find(char)
        if index < 0:
            return False
        value = value * 58 + index
    raw = value.to_bytes(25, "big") if value.bit_length() <= 200 else b""
    if len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    pad = len(address) - len(address.lstrip("1"))
    if raw[:pad] != b"\x00" * pad:
        return False
    checksum = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return checksum == raw[21:]


def _bech32_polymod(values: Sequence[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index in range(5):
            checksum ^= generator[index] if (top >> index) & 1 else 0
    return checksum


def _bech32_valid(address: str) -> bool:
    hrp, _, data = address.rpartition("1")
    if hrp != "bc" or len(data) < 7:
        return False
    try:
        values = [_BECH32_CHARSET.index(char) for char in data]
    except ValueError:
        return False
    expanded = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    constant = _bech32_polymod(expanded + values)
    return constant in (1, 0x2BC830A3)  # bech32 ( v0 ) hoặc bech32m ( v1+ )


def _onion_v3_valid(label: str) -> bool:
    try:
        raw = base64.b32decode(label.upper())
    except (binascii.Error, ValueError):
        return False
    if len(raw) != 35 or raw[34] != 3:
        return False
    digest = hashlib.sha3_256(b".onion checksum" + raw[:32] + b"\x03").digest()
    return digest[:2] == raw[32:34]


# ============================================================ detector chính


class Context:
    """Những gì mọi detector cần: cấu trúc, bể chuỗi, dữ liệu thô."""

    def __init__(self, parsed: Parsed, pool: StringPool, data: bytes) -> None:
        self.parsed = parsed
        self.pool = pool
        self.data = data
        self.hits: List[IndicatorHit] = []
        self.iocs: List[Ioc] = []
        self.notes: List[str] = []
        self.capabilities = match_capabilities(parsed, pool)

    def hit(self, indicator_id: str, evidence: Iterable[Evidence], tier: Optional[Tier] = None) -> IndicatorHit:
        items = list(evidence)[:MAX_EVIDENCE]
        for existing in self.hits:
            if existing.spec.id == indicator_id:
                for item in items:
                    if item not in existing.evidence and len(existing.evidence) < MAX_EVIDENCE:
                        existing.evidence.append(item)
                if tier is not None and (existing.tier_override is None or tier > existing.tier):
                    existing.tier_override = tier
                return existing
        created = IndicatorHit(spec(indicator_id), items, tier)
        self.hits.append(created)
        return created

    def ioc(self, kind: str, value: str, location: str = "") -> None:
        if any(item.kind == kind and item.value == value for item in self.iocs):
            return
        if len(self.iocs) < 200:
            self.iocs.append(Ioc(kind, value, location))


def run_all(context: Context) -> None:
    for detector in DETECTORS:
        detector(context)


# ------------------------------------------------------------ cấu trúc


_WELL_KNOWN_VENDORS = re.compile(
    r"\b(?:microsoft|google|adobe|apple|mozilla|oracle|intel|nvidia|vmware|cisco|symantec|mcafee|kaspersky|eset)\b",
    re.IGNORECASE,
)


def structural(context: Context) -> None:
    parsed = context.parsed
    if parsed.packers:
        context.hit("FSX-S01", [Evidence(name, "dấu vết packer") for name in parsed.packers])
    executable_hot = [
        s for s in parsed.sections if s.executable and s.raw_size >= 4096 and s.entropy >= 7.2
    ]
    if executable_hot:
        context.hit(
            "FSX-S02",
            [Evidence("%s: entropy %.2f trên %d byte" % (s.name or "?", s.entropy, s.raw_size), "offset 0x%x" % s.offset) for s in executable_hot],
        )
    wx = [s for s in parsed.sections if s.writable and s.executable]
    wx_traits = [t.split(":", 1)[1] for t in parsed.traits if t.startswith("wx-segment:")]
    if wx or wx_traits:
        items = [Evidence("section %s" % (s.name or "?"), "offset 0x%x" % s.offset) for s in wx]
        items += [Evidence("segment %s" % name, "program header") for name in wx_traits]
        context.hit("FSX-S03", items)
    empty_exec = [s for s in parsed.sections if s.executable and s.raw_size == 0 and s.virtual_size >= 16384]
    if empty_exec:
        context.hit(
            "FSX-S08",
            [Evidence("%s: 0 byte trên đĩa, %d byte trong bộ nhớ" % (s.name or "?", s.virtual_size)) for s in empty_exec],
        )
    if parsed.family == "pe":
        _pe_structure(context)
    hidden = parsed.metadata.get("_xor_recovered")
    if hidden:
        context.hit("FSX-S15", [Evidence(part.strip(), "chuỗi đã giải") for part in hidden.split("|")])
    if parsed.has_trait("no-section-headers") and not parsed.packers:
        context.hit("FSX-S01", [Evidence("ELF không có bảng section", "header ELF")])
    if parsed.has_trait("obfuscated-names") or (parsed.has_trait(".net") and parsed.packers):
        items = [Evidence(name, "attribute obfuscator") for name in parsed.packers if parsed.has_trait(".net")]
        if parsed.has_trait("obfuscated-names"):
            items.append(Evidence("trên 30% định danh trong #Strings không đọc được", "metadata .NET"))
        context.hit("FSX-S12", items)
    if parsed.family == "script":
        items = []
        if parsed.has_trait("base64-payload"):
            labels = [label for label, _ in parsed.embedded_text if label.startswith("đã giải mã")]
            items += [Evidence(label, "script") for label in labels]
        if parsed.has_trait("obfuscated"):
            items.append(Evidence("nhiều chuỗi bị cắt nhỏ rồi nối lại / ký tự thoát chèn giữa tên lệnh", "script"))
        if parsed.has_trait("encoded-script"):
            items.append(Evidence("Script Encoder ( #@~^ )", "đầu tệp"))
        if items:
            context.hit("FSX-S13", items, None if parsed.has_trait("base64-payload") or parsed.has_trait("encoded-script") else Tier.CONTEXT)
    serious = [a for a in parsed.anomalies if not a.startswith(("bỏ qua", "đã chạm", "kho có", "quá nhiều import"))]
    if serious:
        context.hit("FSX-S14", [Evidence(a, "parser") for a in serious])


def _pe_structure(context: Context) -> None:
    parsed = context.parsed
    size = len(context.data)
    names = [item.name.lower() for item in parsed.imports if item.name]
    if parsed.has_trait(".net"):
        pass  # .NET import mscoree!_CorExeMain là bình thường
    elif size >= 100_000 and len(parsed.imports) <= 10 and not parsed.has_trait("go"):
        resolvers = [n for n in names if n in ("getprocaddress", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "ldrgetprocedureaddress")]
        tier = Tier.SUSPICIOUS if resolvers else Tier.CONTEXT
        items = [Evidence("%d import cho tệp %d byte" % (len(parsed.imports), size), "bảng import")]
        items += [Evidence(name, "import") for name in resolvers]
        context.hit("FSX-S04", items, tier)
    overlay = parsed.overlay
    if overlay and overlay.size >= 65536 and overlay.entropy >= 7.5:
        if overlay.kind:
            context.notes.append(
                "overlay %d byte entropy %.2f được nhận là %s; entropy cao ở đây là bình thường"
                % (overlay.size, overlay.entropy, overlay.kind)
            )
        elif not parsed.has_trait("pyinstaller"):
            context.hit("FSX-S05", [Evidence("%d byte, entropy %.2f" % (overlay.size, overlay.entropy), "offset 0x%x" % overlay.offset)])
    hot_resources = [r for r in parsed.resources if r.size >= 65536 and r.entropy >= 7.5 and r.type not in ("ICON", "BITMAP", "GROUP_ICON")]
    if hot_resources:
        context.hit(
            "FSX-S06",
            [Evidence("%s/%s: %d byte, entropy %.2f" % (r.type, r.name, r.size, r.entropy), "offset 0x%x" % r.offset) for r in hot_resources],
        )
    if parsed.entry_point:
        section = next((s for s in parsed.sections if s.name == parsed.entry_section), None)
        if parsed.entry_section is None:
            context.hit("FSX-S07", [Evidence("entry point 0x%x không thuộc section nào" % parsed.entry_point)])
        elif section is not None and (section.writable or not section.executable):
            context.hit(
                "FSX-S07",
                [Evidence("entry point trong section %s ( %s )" % (section.name, "ghi được" if section.writable else "không đánh dấu thực thi"))],
            )
    odd = [s.name for s in parsed.sections if not re.match(r"^[\x20-\x7e]{1,8}$", s.name or "")]
    if odd:
        context.hit("FSX-S09", [Evidence(repr(name)) for name in odd])
    stamp = parsed.timestamp
    if stamp is not None and not parsed.has_trait(".net") and not parsed.has_trait("go"):
        now = int(time.time())
        if stamp == 0 or stamp > now + 86400 * 2 or stamp < 946684800:
            # Bộ biên dịch MSVC với /Brepro ghi hash thay cho thời gian: giá trị
            # lớn hơn hiện tại là bình thường ở đó, nên chỉ coi là bối cảnh.
            context.hit("FSX-S10", [Evidence("TimeDateStamp = 0x%08x" % stamp, "file header")])
    company = parsed.metadata.get("CompanyName", "") + " " + parsed.metadata.get("ProductName", "")
    match = _WELL_KNOWN_VENDORS.search(company)
    if match and not parsed.signature.present:
        context.hit("FSX-S11", [Evidence("CompanyName / ProductName: %s" % company.strip(), "resource VERSION"), Evidence("không có chữ ký Authenticode", "bảng chứng chỉ")])


# ------------------------------------------------------------ năng lực


def capability(context: Context) -> None:
    caps = context.capabilities
    pool = context.pool
    if caps.has("enumerate"):
        context.hit("FSX-C01", caps.evidence("enumerate"))
    if caps.has("symmetric"):
        context.hit("FSX-C02", caps.evidence("symmetric"))
    if caps.has("asymmetric"):
        context.hit("FSX-C03", caps.evidence("asymmetric"))
    if caps.has("enumerate") and (caps.has("symmetric") or caps.has("asymmetric")) and caps.has("destructive-write"):
        items = [
            Evidence("duyệt tệp: %s" % caps.evidence("enumerate")[0].detail),
            Evidence("mã hoá: %s" % (caps.evidence("symmetric") or caps.evidence("asymmetric"))[0].detail),
            Evidence("ghi đè / đổi tên / xoá: %s" % caps.evidence("destructive-write")[0].detail),
        ]
        context.hit("FSX-C04", items)
    inhibit = _pattern_evidence(RECOVERY_INHIBITION, pool)
    if inhibit:
        context.hit("FSX-C05", inhibit)
    _kill_list(context)
    if caps.has("restart-manager"):
        rm = {_api_key(e.detail.split("!")[-1])[-1] for e in caps.evidence("restart-manager")}
        if len(rm) >= 2:
            context.hit("FSX-C07", caps.evidence("restart-manager"))
    if caps.has("shares"):
        context.hit("FSX-C08", caps.evidence("shares"))
    persistence = _pattern_evidence(PERSISTENCE, pool)
    if persistence:
        context.hit("FSX-C09", persistence)
    self_delete = _pattern_evidence(SELF_DELETE, pool)
    if self_delete:
        context.hit("FSX-C10", self_delete)
    logs = _pattern_evidence(LOG_CLEARING, pool)
    for item in context.parsed.imports:
        if "cleareventlog" in _api_key(item.name):
            logs.append(Evidence("%s!%s" % (item.library, item.name), "import"))
    if logs:
        context.hit("FSX-C11", logs)
    evasion = _pattern_evidence(DEFENSE_EVASION, pool)
    if evasion:
        context.hit("FSX-C12", evasion)
    if caps.has("wallpaper") and WALLPAPER_STRING.search(pool.lower):
        context.hit("FSX-C13", caps.evidence("wallpaper") + [Evidence("chuỗi nhắc tới wallpaper / Control Panel\\Desktop")])
    esxi = _pattern_evidence(ESXI_PATHS, pool)
    if esxi:
        files = sorted({m.group(1) for m in ESXI_FILES.finditer(pool.lower)})
        if len(files) >= 2 or caps.has("service-stop"):
            if files:
                esxi.append(Evidence("đuôi tệp máy ảo: %s" % ", ".join("." + f for f in files)))
            context.hit("FSX-C14", esxi)
    wipe = _pattern_evidence(SECURE_DELETE, pool)
    if wipe:
        context.hit("FSX-C15", wipe)
    raw = _pattern_evidence(RAW_DISK, pool)
    if raw:
        context.hit("FSX-C16", raw)


def _kill_list(context: Context) -> None:
    pool = context.pool
    found: Dict[str, str] = {}
    positions: Dict[str, int] = {}
    for match in _KILL_REGEX.finditer(pool.lower):
        name = match.group(1)
        if name not in found:
            found[name] = _KILL_LOOKUP[name]
            positions[name] = match.start()
    groups = {group for group in found.values()}
    caps = context.capabilities
    # Ngưỡng: ít nhất 6 tên khác nhau trải trên ít nhất 2 nhóm. Một trình cài
    # đặt Office đóng Word/Excel/Outlook chỉ chạm một nhóm nên không bắn.
    if len(found) >= 6 and len(groups) >= 2:
        items = [
            Evidence(
                "%d tên thuộc %d nhóm ( %s )" % (len(found), len(groups), ", ".join(sorted(groups))),
                "danh sách chuỗi",
            )
        ]
        for name in list(found)[:5]:
            items.append(Evidence(name, _location(pool, positions[name])))
        if caps.has("service-stop"):
            items.append(Evidence("cơ chế dừng: %s" % caps.evidence("service-stop")[0].detail))
        context.hit("FSX-C06", items)


# ------------------------------------------------------------ nội dung


def ransom_note(context: Context) -> None:
    pool = context.pool
    lower = pool.lower
    events: List[Tuple[int, int, str]] = []
    for category, regex in NOTE_PHRASES.items():
        for count, match in enumerate(regex.finditer(lower)):
            events.append((match.start(), match.end(), category))
            if count >= 400:
                break
    events.sort()
    best: Tuple[int, int, int, Set[str]] = (0, 0, 0, set())
    left = 0
    window: Dict[str, int] = {}
    for right, (start, _, category) in enumerate(events):
        window[category] = window.get(category, 0) + 1
        while events[left][0] < start - NOTE_WINDOW:
            old = events[left][2]
            window[old] -= 1
            if not window[old]:
                del window[old]
            left += 1
        if len(window) > len(best[3]):
            best = (events[left][0], events[right][1], right, set(window))
    categories = best[3]
    if len(categories) >= 3 and categories & {"encrypted", "decrypt"} and categories & {"payment", "contact", "threat", "identity"}:
        start, end = best[0], best[1]
        tier = Tier.STRONG if len(categories) >= 4 or {"encrypted", "payment"} <= categories else Tier.SUSPICIOUS
        items = [
            Evidence("%d nhóm cụm từ: %s" % (len(categories), ", ".join(sorted(categories))), _location(pool, start)),
            Evidence(_snippet(pool.text, start, min(end, start + 240), 0)[:300], "trích đoạn"),
        ]
        context.hit("FSX-T01", items, tier)
        segment = pool.text[max(0, start - 200) : end + 400]
        for match in _VICTIM_ID.finditer(segment):
            context.ioc("victim-or-campaign-id", match.group(1), "trong ghi chú")
    for value, location in _unique_matches(NOTE_FILENAME, pool):
        context.ioc("ransom-note-filename", value.strip(" !#_-[]+"), location)
    names = [item for item in context.iocs if item.kind == "ransom-note-filename"]
    if names:
        context.hit("FSX-T02", [Evidence(item.value, item.location) for item in names])


def _unique_matches(regex: "re.Pattern[str]", pool: StringPool, group: int = 0, limit: int = 32) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    text = pool.text
    for match in regex.finditer(pool.lower):
        value = text[match.start(group) : match.end(group)]
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append((value, _location(pool, match.start(group))))
        if len(found) >= limit:
            break
    return found


def addresses(context: Context) -> None:
    pool = context.pool
    verified_onions = []
    for value, location in _unique_matches(_ONION_V3, pool, 1):
        if _onion_v3_valid(value.lower()):
            verified_onions.append(Evidence(value.lower() + ".onion", location + ", checksum v3 hợp lệ"))
            context.ioc("onion", value.lower() + ".onion", location)
    legacy = []
    for value, location in _unique_matches(_ONION_V2, pool, 1):
        legacy.append(Evidence(value.lower() + ".onion", location + ", dạng v2 cũ, không có checksum để kiểm"))
        context.ioc("onion", value.lower() + ".onion", location)
    if verified_onions:
        context.hit("FSX-T03", verified_onions + legacy)
    elif legacy:
        context.hit("FSX-T03", legacy, Tier.CONTEXT)

    wallets = []
    for value, location in _unique_matches(_BTC_BASE58, pool, 1):
        if _base58check(value):
            wallets.append(Evidence(value, location + ", Bitcoin, checksum hợp lệ"))
            context.ioc("bitcoin", value, location)
    for value, location in _unique_matches(_BTC_BECH32, pool, 1):
        if _bech32_valid(value.lower()):
            wallets.append(Evidence(value, location + ", Bitcoin bech32, checksum hợp lệ"))
            context.ioc("bitcoin", value, location)
    monero = []
    for value, location in _unique_matches(_MONERO, pool, 1):
        monero.append(Evidence(value, location + ", Monero ( chưa kiểm checksum )"))
        context.ioc("monero", value, location)
    if wallets:
        context.hit("FSX-T04", wallets + monero)
    elif monero:
        context.hit("FSX-T04", monero, Tier.CONTEXT)

    contacts = []
    for value, location in _unique_matches(_ANON_EMAIL, pool):
        contacts.append(Evidence(value, location))
        context.ioc("email", value, location)
    for regex, kind in ((_TOX_ID, "tox-id"), (_SESSION_ID, "session-id")):
        for value, location in _unique_matches(regex, pool, 1):
            contacts.append(Evidence("%s: %s" % (kind, value), location))
            context.ioc(kind, value, location)
    if contacts:
        context.hit("FSX-T05", contacts)


def target_lists(context: Context) -> None:
    pool = context.pool
    extensions: Set[str] = set()
    first_location = ""
    for value, offset, label in pool.iter_strings():
        if len(value) > 2000:
            continue
        lowered = value.strip().lower()
        alone = _EXTENSION_ALONE.match(lowered)
        if alone and alone.group(1) in TARGET_EXTENSIONS:
            extensions.add(alone.group(1))
            continue
        if len(lowered) >= 20 and _EXTENSION_LIST.match(lowered):
            tokens = {t.lstrip("*.") for t in re.split(r"[\s,;|]+", lowered) if t}
            matched = tokens & TARGET_EXTENSIONS
            if len(matched) >= 5:
                extensions |= matched
                if not first_location:
                    first_location = ("offset 0x%x" % offset) if offset >= 0 else "dòng %d" % -offset
    if len(extensions) >= 25:
        sample = ", ".join("." + item for item in sorted(extensions)[:20])
        context.hit(
            "FSX-T06",
            [Evidence("%d đuôi tệp mục tiêu khác nhau" % len(extensions), first_location or "chuỗi rời"), Evidence(sample + ( " ..." if len(extensions) > 20 else ""))],
        )
    exclusions: Dict[str, int] = {}
    for match in _EXCLUSION_REGEX.finditer(pool.lower):
        exclusions.setdefault(match.group(1), match.start())
    if len(exclusions) >= 5:
        context.hit(
            "FSX-T07",
            [Evidence("%d mục loại trừ hệ thống: %s" % (len(exclusions), ", ".join(sorted(exclusions)[:12])))]
            + [Evidence(name, _location(pool, position)) for name, position in list(exclusions.items())[:3]],
        )


def keys_and_constants(context: Context) -> None:
    data = context.data
    pool = context.pool
    ignore = _signature_ranges(context.parsed)
    keys: List[Evidence] = []
    for match in _PEM_PUBLIC.finditer(pool.lower):
        keys.append(Evidence("khoá công khai dạng PEM", _location(pool, match.start())))
        if len(keys) >= 4:
            break
    position = data.find(_CRYPTOAPI_PUBLICKEYBLOB)
    if position >= 0:
        bits = int.from_bytes(data[position + 12 : position + 16], "little")
        keys.append(Evidence("PUBLICKEYBLOB của CryptoAPI ( RSA %d bit )" % bits, "offset 0x%x" % position))
    bcrypt = _bcrypt_rsa_blobs(data)
    keys.extend(bcrypt)
    spki = []
    start = 0
    while len(spki) < 16:
        position = data.find(_SPKI_RSA, start)
        if position < 0:
            break
        start = position + 1
        if any(low <= position < high for low, high in ignore):
            continue
        spki.append(position)
    if 1 <= len(spki) <= 3:
        keys.extend(Evidence("SubjectPublicKeyInfo RSA ( DER )", "offset 0x%x" % p) for p in spki)
    elif len(spki) > 3:
        context.notes.append(
            "có %d khoá RSA dạng DER ngoài vùng chữ ký; nhiều như vậy thường là kho chứng chỉ gốc nhúng sẵn, không tính là khoá của kẻ tấn công"
            % len(spki)
        )
    if keys:
        context.hit("FSX-T08", keys)
    constants = []
    for label, needle in (
        ("AES S-box ( mã hoá )", AES_SBOX_PREFIX),
        ("AES S-box nghịch ( giải mã )", AES_INV_SBOX_PREFIX),
        ("hằng sigma ChaCha / Salsa", CHACHA_SIGMA[0]),
        ("hằng tau ChaCha / Salsa", CHACHA_SIGMA[1]),
    ):
        position = data.find(needle)
        if position >= 0:
            constants.append(Evidence(label, "offset 0x%x" % position))
    if constants:
        context.hit("FSX-T09", constants)


def _signature_ranges(parsed: Parsed) -> List[Tuple[int, int]]:
    ranges = []
    raw = parsed.metadata.get("_signature_range")
    if raw:
        low, high = (int(part) for part in raw.split(":"))
        ranges.append((low, high))
    return ranges


def _bcrypt_rsa_blobs(data: bytes) -> List[Evidence]:
    found: List[Evidence] = []
    start = 0
    while len(found) < 4:
        position = data.find(b"RSA1", start)
        if position < 0:
            break
        start = position + 4
        header = data[position : position + 24]
        if len(header) < 24:
            break
        bits = int.from_bytes(header[4:8], "little")
        exponent = int.from_bytes(header[8:12], "little")
        modulus = int.from_bytes(header[12:16], "little")
        primes = header[16:24]
        if bits in (1024, 2048, 3072, 4096, 8192) and 1 <= exponent <= 8 and modulus * 8 == bits and primes == b"\x00" * 8:
            found.append(Evidence("BCRYPT_RSAPUBLIC_BLOB ( RSA %d bit )" % bits, "offset 0x%x" % position))
    return found


DETECTORS = (structural, capability, ransom_note, addresses, target_lists, keys_and_constants)
