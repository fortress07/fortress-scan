"""Elixir: Phoenix controller, LiveView, Ecto.

Tham số request đến qua mẫu khớp ở đầu hàm ( `def show(conn, %{"id" => id})` )
và chỉ có giá trị trong thân `do ... end` của đúng hàm đó. `a |> f(b)` là
`f(a, b)`, và sigil `~s(...)` là chuỗi.
"""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.languages import ELIXIR, detect_language

DIRECTIVE = "fortress-scan: ignore-file"


def hits(source: str):
    return sorted((f.rule_id, f.line) for f in scan_source(source, ELIXIR, "mau", Config()))


def test_controller_params_reach_sql_shell_and_external_redirect():
    source = (
        "defmodule AppWeb.PageController do\n"
        "  def search(conn, %{\"q\" => q}) do\n"
        "    {:ok, r} = Ecto.Adapters.SQL.query(Repo, \"SELECT * FROM t WHERE n = '#{q}'\", [])\n"
        "    Repo.query!(\"SELECT * FROM t WHERE n = $1\", [q])\n"
        "    json(conn, r.rows)\n"
        "  end\n"
        "\n"
        "  def go(conn, params) do\n"
        "    redirect(conn, external: params[\"next\"])\n"
        "  end\n"
        "\n"
        "  def stay(conn, params) do\n"
        "    redirect(conn, to: params[\"next\"])\n"
        "  end\n"
        "\n"
        "  def ping(conn, %{\"host\" => host}) do\n"
        "    System.cmd(\"ping\", [\"-c\", \"1\", host])\n"
        "    :os.cmd(String.to_charlist(\"ping -c 1 \" <> host))\n"
        "    System.cmd(\"sh\", [\"-c\", \"ping #{host}\"])\n"
        "    text(conn, \"ok\")\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [
        ("FSB-CMD-001", 18),
        ("FSB-CMD-001", 19),
        ("FSB-REDIR-001", 9),
        ("FSB-SQL-001", 3),
    ]


def test_params_are_scoped_to_the_action_body():
    # `defp helper(conn, message)` không phải action: message không đến từ request.
    source = (
        "defmodule A do\n"
        "  def run(conn, params) do\n"
        "    System.shell(params[\"cmd\"])\n"
        "  end\n"
        "\n"
        "  defp helper(conn, params) do\n"
        "    System.shell(params)\n"
        "  end\n"
        "\n"
        "  def later(x), do: System.shell(\"echo \" <> params_text())\n"
        "end\n"
    )
    assert hits(source) == [("FSB-CMD-001", 3), ("FSB-CMD-003", 7), ("FSB-CMD-003", 10)]


def test_pipes_feed_the_first_argument_and_sanitizers_in_the_pipe_count():
    source = (
        "defmodule A do\n"
        "  def file(conn, %{\"name\" => name}) do\n"
        "    path = Path.join(\"/srv/files\", name)\n"
        "    conn\n"
        "    |> put_resp_content_type(\"text/plain\")\n"
        "    |> send_file(200, path)\n"
        "  end\n"
        "\n"
        "  def safe(conn, params) do\n"
        "    params[\"f\"] |> Path.basename() |> File.read!()\n"
        "    params[\"cmd\"]\n"
        "    |> String.trim()\n"
        "    |> System.shell()\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [("FSB-CMD-001", 13), ("FSB-PATH-001", 6)]


def test_send_download_only_for_a_file_tuple():
    source = (
        "defmodule A do\n"
        "  def download(conn, %{\"data\" => data, \"f\" => f}) do\n"
        "    send_download(conn, {:binary, data}, filename: \"x.txt\")\n"
        "    send_download(conn, {:file, f})\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [("FSB-PATH-001", 4)]


def test_liveview_event_params_reach_eval_raw_and_binary_to_term():
    source = (
        "defmodule AppWeb.ThingLive do\n"
        "  def mount(%{\"id\" => id}, _session, socket) do\n"
        "    {:ok, assign(socket, html: raw(\"<b>\" <> id <> \"</b>\"))}\n"
        "  end\n"
        "\n"
        "  def handle_event(\"eval\", %{\"code\" => code}, socket) do\n"
        "    {result, _} = Code.eval_string(code)\n"
        "    {:noreply, assign(socket, result: result)}\n"
        "  end\n"
        "\n"
        "  def handle_event(\"load\", params, socket) do\n"
        "    :erlang.binary_to_term(Base.decode64!(params[\"t\"]))\n"
        "    Plug.Crypto.non_executable_binary_to_term(Base.decode64!(params[\"t\"]))\n"
        "    {:noreply, socket}\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [("FSB-DESER-001", 12), ("FSB-EXEC-001", 7), ("FSB-XSS-001", 3)]


def test_sigils_heredocs_and_module_attributes():
    source = (
        "defmodule B do\n"
        "  @re ~r/#not-a-comment/\n"
        "  @csp \"default-src 'self'; script-src 'nonce-<%= nonce %>'\"\n"
        "  def q(name) do\n"
        "    sql = ~s(SELECT * FROM users WHERE name = '#{name}')\n"
        "    Repo.query!(sql)\n"
        "    Repo.query!(~S(SELECT * FROM users WHERE name = '#{name}'))\n"
        "    c = ?#\n"
        "    EEx.eval_string(@csp, nonce: name)\n"
        "    Repo.query!(\"SELECT 1\")\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [("FSB-SQL-002", 6)]


def test_query_only_taint_does_not_choose_the_redirect_host():
    source = (
        "defmodule A do\n"
        "  def go(conn, params) do\n"
        "    qs = if params[\"q\"] == nil, do: \"\", else: \"?\" <> params[\"q\"]\n"
        "    redirect(conn, external: Endpoint.url() <> \"/search\" <> qs)\n"
        "    url = URI.parse(Application.get_env(:app, :idp_url))\n"
        "    redirect(conn, external: URI.to_string(%{url | query: URI.encode_query(params)}))\n"
        "    redirect(conn, external: URI.to_string(%{url | host: params[\"h\"]}))\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [("FSB-REDIR-001", 7)]


def test_project_file_abstractions_are_not_the_file_module():
    source = (
        "defmodule A do\n"
        "  def open(conn, %{\"path\" => path}) do\n"
        "    Livebook.FileSystem.File.read(path)\n"
        "    File.read!(path)\n"
        "  end\n"
        "end\n"
    )
    assert hits(source) == [("FSB-PATH-001", 4)]


def test_elixir_files_and_scripts_map_to_elixir(tmp_path: Path):
    for name in ("router.ex", "mix.exs"):
        path = tmp_path / name
        path.write_text("defmodule A do\nend\n", encoding="utf-8")
        assert detect_language(path) == ELIXIR
    script = tmp_path / "deploy"
    script.write_text("#!/usr/bin/env elixir\nIO.puts(1)\n", encoding="utf-8")
    assert detect_language(script) == ELIXIR


SINK = (
    "defmodule A do\n"
    "  def run(conn, params) do\n"
    "    System.shell(params[\"cmd\"])\n"
    "  end\n"
    "end\n"
)


def _scan(tmp_path: Path, source: str) -> Tuple[int, int]:
    (tmp_path / "a.ex").write_text(source, encoding="utf-8")
    result = scan(str(tmp_path), Config())
    return len(result.findings), result.suppressed


def test_a_directive_inside_a_sigil_is_data(tmp_path: Path):
    source = "@note ~s(tai lieu # %s)\n" % DIRECTIVE + SINK
    assert _scan(tmp_path, source) == (1, 0)


def test_a_char_literal_quote_does_not_open_a_string(tmp_path: Path):
    # `?"` là một ký tự. Đọc nó là mở chuỗi thì chuỗi giả đóng ở dấu nháy mở của
    # dòng sau, và ruột chuỗi thật lộ ra thành một "chú thích".
    source = 'q = ?"\nnote = "# %s"\n' % DIRECTIVE + SINK
    assert _scan(tmp_path, source) == (1, 0)


def test_a_real_elixir_comment_still_suppresses(tmp_path: Path):
    source = "# %s\n" % DIRECTIVE + SINK
    assert _scan(tmp_path, source) == (0, 1)
