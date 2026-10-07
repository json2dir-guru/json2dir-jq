# json2dir evaluator written in jq: strict UTF-8 check, JSON parser, validation of the
# whole document (RFC J2D-1 sections 3, 4) and generation of a POSIX shell script.
# Run as: jq -n -j --rawfile input FILE -f json2dir.jq
# jq's own JSON parser is not used: it is too lax (duplicate keys, lone surrogates, huge
# numbers), so the raw text is tokenized and parsed here.

def fail(msg): error("json2dir: " + msg);
def has($c): (split($c) | length) > 1;
# Join an array of strings. Not join("") (quadratic in jq 1.8) and not `add // ""`: the
# alternative operator keeps a backtrack point that forces a copy of a reduce state.
def concat: if length == 0 then "" else add end;

# --- Strict UTF-8 ------------------------------------------------------------------------
# jq decodes --rawfile as UTF-8 and replaces every invalid sequence (bad byte, overlong,
# encoded surrogate, > U+10FFFF, truncated) with U+FFFD; the bytes themselves are never
# visible to a jq program. So U+FFFD in the decoded text is the signal for invalid input.
# Limitation: a literal (unescaped) U+FFFD in an otherwise valid document is also rejected;
# the escape \ufffd is fine.
def utf8_text:
  if has([65533] | implode) then fail("input is not valid UTF-8 (or contains a raw U+FFFD)")
  # A byte order mark at the start is ignored, as RFC 8259 permits.
  elif startswith([65279] | implode) then .[1:]
  else . end;

# --- Tokenizer ---------------------------------------------------------------------------
# Splitting at '"' (a literal split, linear) separates string literals from the structural
# text between them; a '"' preceded by an odd number of backslashes stays inside the string.
# Performance notes for jq 1.8: a regex scan over the whole text is quadratic, every
# match/test call compiles its regex again, `+=` and join copy their whole target each time.
# So arrays grow with .a[.a|length] = x, strings are joined with add, and all string literals
# are checked against the strict JSON string grammar with ONE regex test at the end.
def string_re: "^(?:(?:[^\"\\\\\\x00-\\x1f]|\\\\[\"\\\\/bfnrt]|\\\\u[0-9a-fA-F]{4})*\")*$";

def trailing_backslashes:
  if endswith("\\") then (explode | reverse | (map(. == 92) | index(false)) as $k | if $k == null then length else $k end) else 0 end;

# Outside string literals, a valid json2dir document can only contain whitespace and
# punctuation: numbers, true, false and null are never allowed values.
def outside_tokens:
  explode[]
  | select(. != 32 and . != 9 and . != 10 and . != 13)
  | if . == 123 or . == 125 or . == 91 or . == 93 or . == 44 or . == 58 then [.] | implode
    elif . == 116 or . == 102 then fail("booleans are not allowed")
    elif . == 110 then fail("null is not allowed")
    elif . == 45 or (. >= 48 and . <= 57) then fail("numbers are not allowed")
    else fail("invalid JSON: unexpected " + ([.] | implode | tojson)) end;

def tokens:
  split("\"") as $pieces
  | ($pieces | length) as $n
  | reduce range(0; $n) as $i ({toks: [], instr: false, cur: [], bs: 0};
      $pieces[$i] as $p
      | if .instr | not then
          reduce ($p | outside_tokens) as $tok (.; .toks[.toks | length] = $tok)
          | if $i < $n - 1 then .instr = true | .cur = [] | .bs = 0 else . end
        else
          .cur[.cur | length] = $p
          | ($p | trailing_backslashes) as $t
          | .bs = (if $t == ($p | length) then .bs + $t else $t end)
          | if $i == $n - 1 then fail("unterminated string")
            elif .bs % 2 == 1 then .cur[.cur | length] = "\"" | .bs = 0
            else .toks[.toks | length] = "\"" + (.cur | concat) | .instr = false
            end
        end)
  | .toks
  # Each literal is stored as '"' + content; check them all as content + '"' in one go.
  | if [.[] | select(startswith("\"")) | .[1:] + "\""] | concat | test(string_re) then .
    else fail("invalid string literal (control character or bad escape)") end;

# --- String literals ---------------------------------------------------------------------
def hexval: ascii_downcase | explode
  | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 else $c - 48 end));

def simple_escape: {"\"": 34, "\\": 92, "/": 47, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}[.];

# Input: a validated string token (leading '"' only). Split at backslashes: every piece after
# the first starts with an escape letter, except that "\\" leaves an empty piece whose
# following piece is plain text. Escapes become code units (numbers); surrogate pairs are
# joined and lone surrogates rejected.
def unescape:
  .[1:] as $s
  | if ($s | has("\\") | not) then $s
    else
      ($s | split("\\")) as $ps
      | (reduce range(1; $ps | length) as $i ({parts: [$ps[0]], skip: false};
          $ps[$i] as $p
          | if .skip then .parts[.parts | length] = $p | .skip = false
            elif $p == "" then .parts[.parts | length] = 92 | .skip = true
            elif $p[0:1] == "u" then .parts[.parts | length] = ($p[1:5] | hexval)
              | .parts[.parts | length] = $p[5:]
            else .parts[.parts | length] = ($p[0:1] | simple_escape)
              | .parts[.parts | length] = $p[1:] end)
         | .parts | map(select(. != "")))
      | reduce .[] as $p ({out: [], hi: null};
          if ($p | type) == "string" then
            if .hi != null then fail("unpaired surrogate escape") else .out[.out | length] = $p end
          elif $p >= 55296 and $p <= 56319 then
            if .hi != null then fail("unpaired surrogate escape") else .hi = $p end
          elif $p >= 56320 and $p <= 57343 then
            if .hi == null then fail("unpaired surrogate escape")
            else .out[.out | length] = ([65536 + (.hi - 55296) * 1024 + ($p - 56320)] | implode)
              | .hi = null end
          else
            if .hi != null then fail("unpaired surrogate escape")
            else .out[.out | length] = ([$p] | implode) end
          end)
      | if .hi != null then fail("unpaired surrogate escape") else .out | concat end
    end;

# --- Parser ------------------------------------------------------------------------------
# A state machine over the tokens with an explicit stack of open containers (recursion with
# values passed as arguments would copy them at every step).
# Modes: value, value_or_end (after '['), key, key_or_end (after '{'), colon, sep, done.
# Duplicate member names: the last occurrence wins (RFC J2D-1 section 4).
def parse($t):
  def attach($v):
    if (.stack | length) == 0 then .doc = $v | .mode = "done"
    else (.stack | length - 1) as $top
      | if (.stack[$top].c | type) == "object" then .stack[$top].c[.stack[$top].k] = $v
        else .stack[$top].c[.stack[$top].c | length] = $v end
      | .mode = "sep"
    end;
  def close:
    .stack[-1].c as $v | .stack |= .[:-1] | attach($v);
  reduce $t[] as $k ({stack: [], mode: "value", doc: null};
    if .mode == "done" then fail("trailing data after the document")
    elif .mode == "value" or .mode == "value_or_end" then
      if $k == "]" and .mode == "value_or_end" then close
      elif $k == "{" then .stack[.stack | length] = {c: {}, k: null} | .mode = "key_or_end"
      elif $k == "[" then .stack[.stack | length] = {c: []} | .mode = "value_or_end"
      elif $k | startswith("\"") then attach($k | unescape)
      else fail("unexpected " + ($k | tojson)) end
    elif .mode == "key" or .mode == "key_or_end" then
      if $k == "}" and .mode == "key_or_end" then close
      elif $k | startswith("\"") then .stack[-1].k = ($k | unescape) | .mode = "colon"
      else fail("expected a member name") end
    elif .mode == "colon" then
      if $k == ":" then .mode = "value" else fail("expected ':'") end
    else # sep
      if (.stack[-1].c | type) == "object" then
        if $k == "," then .mode = "key" elif $k == "}" then close else fail("expected ',' or '}'") end
      else
        if $k == "," then .mode = "value" elif $k == "]" then close else fail("expected ',' or ']'") end
      end
    end)
  | if .mode != "done" then fail("unexpected end of input") else .doc end;

# --- Shell generation --------------------------------------------------------------------
# (join is quadratic in jq 1.8, add is linear.)
def q: "'" + (split("'") | [.[0], (.[1:][] | "'\\''" + .)] | add) + "'";

# NUL cannot travel in a shell argument, so content is passed as the words between NULs;
# the script writes them joined by NUL bytes using a constant printf format.
# (jq splits "" into [], so empty content is one empty word.)
def content: (if . == "" then [""] else split("\u0000") end) | map(" " + q) | add;

def check_name($p):
  if . == "" or . == "." or . == ".." or has("/") or has("\u0000")
  then fail("invalid name " + tojson + " at " + $p) else . end;

def tree($dir):
  . as $o
  | [keys[] as $k
     | ($dir + "/" + $k) as $p
     | ($k | check_name($p))
     | $o[$k] as $v
     | ($v | type) as $ty
     | if $ty == "object" then "_j2d_dir " + ($p | q) + "\n" + ($v | tree($p))
       elif $ty == "string" then "_j2d_file " + ($p | q) + ($v | content) + "\n"
       elif $ty == "array" then
         if ($v | length) != 2 or ($v[0] | type) != "string" or ($v[1] | type) != "string" then
           fail("an array must be [\"link\", target] or [\"script\", content] at " + $p)
         elif $v[0] == "script" then "_j2d_script " + ($p | q) + ($v[1] | content) + "\n"
         elif $v[0] != "link" then fail("unknown array kind " + ($v[0] | tojson) + " at " + $p)
         # A symlink target cannot contain NUL (RFC section 10).
         elif $v[1] | has("\u0000") then fail("a link target cannot contain NUL at " + $p)
         else "_j2d_link " + ($p | q) + " " + ($v[1] | q) + "\n" end
       else fail($ty + " values are not allowed at " + $p) end]
  | concat;

def helpers: "set -eu
_j2d_fail() { printf 'json2dir: cannot create %s\\n' \"$1\" >&2; exit 1; }
# Remove an existing non-directory (a symlink itself, never its target);
# a real directory in the way of a non-object is an error.
_j2d_clear() {
  if [ -L \"$1\" ]; then rm -f -- \"$1\" || _j2d_fail \"$1\"
  elif [ -d \"$1\" ]; then printf 'json2dir: a directory is in the way: %s\\n' \"$1\" >&2; exit 1
  elif [ -e \"$1\" ]; then rm -f -- \"$1\" || _j2d_fail \"$1\"
  fi
}
_j2d_dir() {
  if [ -L \"$1\" ] || { [ -e \"$1\" ] && [ ! -d \"$1\" ]; }; then rm -f -- \"$1\" || _j2d_fail \"$1\"; fi
  if [ ! -d \"$1\" ]; then mkdir -- \"$1\" || _j2d_fail \"$1\"; fi
}
# _j2d_file path part...: the content is the parts joined by NUL bytes.
_j2d_file() {
  _j2d_clear \"$1\"
  _j2d_path=$1; shift
  {
    printf '%s' \"$1\"; shift
    for _j2d_part in \"$@\"; do printf '\\000%s' \"$_j2d_part\"; done
  } > \"$_j2d_path\" || _j2d_fail \"$_j2d_path\"
}
_j2d_script() { _j2d_file \"$@\"; chmod a+x -- \"$1\" || _j2d_fail \"$1\"; }
_j2d_link() { _j2d_clear \"$1\"; ln -s -- \"$2\" \"$1\" || _j2d_fail \"$1\"; }
";

$input
| utf8_text
| tokens
| parse(.)
| if type != "object" then fail("the root of the document must be an object") else . end
| helpers + tree(".") + "# json2dir: end\n"
