"""BUGDNA analysis engine: fingerprint, similarity, pattern, root cause. Pure stdlib."""
import re, math, hashlib, sqlite3, json, time, os
from collections import Counter

# category: (label, regex signals, root cause, fixes)
CATS = {
 "null_ref": ("Null / undefined reference", r"nonetype|undefined|null ?pointer|cannot read propert|nullreference|is not (a function|defined)",
   "A value was assumed to exist but is empty at this point, usually because an earlier lookup, API call or init step returned nothing.",
   ["Guard the access (`if x is not None` / optional chaining `?.`).", "Trace where the value is produced and handle its empty case there.", "Add a test that feeds the empty/missing input."]),
 "index_bounds": ("Index out of bounds", r"indexerror|out of range|outofbounds|out of bounds|list index",
   "A loop or lookup uses an index beyond the collection length, often an off-by-one or an empty list.",
   ["Check `len()` before indexing.", "Review loop bounds (`<` vs `<=`).", "Handle the empty-collection case explicitly."]),
 "key_missing": ("Missing key / property", r"keyerror|missing key|key not found|no such (key|field)|unexpected keyword",
   "Code expects a field that the incoming data does not contain, typically a changed or partial payload.",
   ["Use `.get(key, default)` or schema validation (pydantic/zod).", "Log the raw payload when the key is absent.", "Version or document the data contract."]),
 "type_mismatch": ("Type / value mismatch", r"typeerror|valueerror|invalid literal|cannot convert|unsupported operand|nan\b|not iterable",
   "A value of the wrong type reached an operation; input was not parsed or validated at the boundary.",
   ["Validate and coerce input at the boundary.", "Print `type(x)` at the failing line.", "Add type hints and a type checker (mypy/tsc)."]),
 "import_dep": ("Import / dependency failure", r"modulenotfound|importerror|no module named|cannot find module|package .* not found|version conflict",
   "The runtime environment is missing a package or has the wrong version/path.",
   ["Install from the pinned requirements file in the active environment.", "Check which interpreter/venv runs the code.", "Pin versions and rebuild a clean environment."]),
 "async_race": ("Async / race condition", r"race|unhandled (promise )?rejection|await|promise|deadlock|event loop|concurren|intermittent|flaky|sometimes",
   "Operations run in an unexpected order or share state without coordination, so failure depends on timing.",
   ["Await every async call and catch rejections.", "Protect shared state with a lock or make it immutable.", "Reproduce with artificial delays to confirm the ordering."]),
 "memory": ("Memory exhaustion / leak", r"memoryerror|out of memory|heap|oom|leak|memory (grows|usage)|killed",
   "Objects are retained or loaded all at once, so memory grows until the process is killed.",
   ["Stream or paginate large data instead of loading it whole.", "Remove lingering references (caches, listeners, globals).", "Profile with tracemalloc / heap snapshots."]),
 "db_conn": ("Database / network connection", r"econnrefused|connection (refused|reset|timed out)|too many connections|operationalerror|timeout|database is locked|pool",
   "The service cannot reach, or has exhausted, a dependency such as a database or API.",
   ["Verify host, port and credentials, and that the service is up.", "Use a bounded connection pool and close connections.", "Add retry with backoff and timeouts."]),
 "cors_auth": ("CORS / auth rejection", r"cors|access-control|\b40[13]\b|unauthorized|forbidden|csrf|invalid token|jwt",
   "The server rejected the request because of origin policy or missing/expired credentials.",
   ["Allow the exact frontend origin in server CORS config.", "Send the auth header/cookie and refresh expired tokens.", "Check the preflight (OPTIONS) response in the network tab."]),
 "syntax": ("Syntax / parse error", r"syntaxerror|unexpected token|indentationerror|unexpected eof|parse error|invalid syntax|json\.?decode|jsondecode",
   "The code or data being parsed is malformed: a missing bracket, bad indentation, or non-JSON response.",
   ["Look at the line before the reported one.", "Run a linter/formatter.", "For JSON, log the raw response body before parsing."]),
 "recursion": ("Runaway recursion", r"recursionerror|maximum call stack|stack overflow|too much recursion",
   "A recursive call lacks a reachable base case or loops back on itself.",
   ["Verify the base case and that each call shrinks the input.", "Add a visited-set for cyclic data.", "Convert to an iterative loop."]),
 "encoding": ("Encoding / locale issue", r"unicodedecode|unicodeencode|codec|utf-?8|encoding|mojibake|charmap",
   "Text was read or written with a different character encoding than it was produced in.",
   ["Open files with `encoding='utf-8'` explicitly.", "Normalize at the input boundary.", "Check the Content-Type charset."]),
}
GENERIC = ("Unclassified / logic bug", "", "No known failure signature matched; likely a logic error where behavior differs from intent.",
   ["Write a minimal reproduction.", "Log inputs and intermediate values around the failure.", "Bisect recent changes (git bisect)."])

# (id, category, language, title, error, resolution, year-month)
SEED = [
 ("H-101","null_ref","python","Profile page crashes for new users","AttributeError: 'NoneType' object has no attribute 'name'","Added default profile on signup and a None guard","2025-11"),
 ("H-102","null_ref","javascript","Dashboard blank after login","TypeError: Cannot read properties of undefined (reading 'map')","Defaulted API list to [] and used optional chaining","2025-12"),
 ("H-103","null_ref","java","Checkout NullPointerException","java.lang.NullPointerException at CartService.total","Initialized cart in constructor, added Optional","2026-01"),
 ("H-104","index_bounds","python","Report export fails on empty month","IndexError: list index out of range","Handled empty result set before indexing","2025-10"),
 ("H-105","index_bounds","java","Pagination off-by-one","ArrayIndexOutOfBoundsException: Index 10 out of bounds for length 10","Changed loop bound from <= to <","2026-02"),
 ("H-106","key_missing","python","Webhook handler KeyError","KeyError: 'customer_id'","Switched to .get() with schema validation","2026-03"),
 ("H-107","key_missing","javascript","Settings page undefined field","TypeError: Cannot read properties of undefined (reading 'theme')","Added default settings merge","2026-01"),
 ("H-108","type_mismatch","python","Price parsing breaks on commas","ValueError: invalid literal for int() with base 10: '1,200'","Strip separators and parse as Decimal","2025-09"),
 ("H-109","type_mismatch","javascript","Total shows NaN","TypeError: unsupported operand, NaN in cart total","Coerced form strings to numbers on input","2026-04"),
 ("H-110","import_dep","python","Deploy fails with missing module","ModuleNotFoundError: No module named 'requests'","Added to requirements.txt, rebuilt image","2026-05"),
 ("H-111","import_dep","javascript","Build cannot find module","Error: Cannot find module 'react-dom/client'","Aligned react and react-dom versions","2026-02"),
 ("H-112","async_race","javascript","Order saved twice intermittently","Unhandled promise rejection; duplicate write on double click","Disabled button while pending, added idempotency key","2026-03"),
 ("H-113","async_race","python","Counter loses updates under load","Race condition: shared counter updated from threads","Guarded with threading.Lock","2025-12"),
 ("H-114","memory","python","Worker killed after hours","MemoryError / process killed (OOM)","Streamed rows in chunks, cleared cache","2026-01"),
 ("H-115","memory","javascript","Tab slows over time","Heap grows; event listeners never removed","Removed listeners on unmount","2026-04"),
 ("H-116","db_conn","python","API 500s at peak","OperationalError: too many connections","Bounded pool size, closed sessions","2026-02"),
 ("H-117","db_conn","javascript","Service cannot reach Postgres","Error: connect ECONNREFUSED 127.0.0.1:5432","Fixed host env var for container network","2026-05"),
 ("H-118","cors_auth","javascript","Frontend blocked calling API","CORS policy: No 'Access-Control-Allow-Origin' header","Added frontend origin to CORS middleware","2025-11"),
 ("H-119","cors_auth","python","Random 401 after an hour","401 Unauthorized: token expired","Implemented refresh-token flow","2026-03"),
 ("H-120","syntax","javascript","App fails to parse API reply","SyntaxError: Unexpected token '<' in JSON at position 0","Server returned HTML error page; fixed route and checked status","2026-01"),
 ("H-121","syntax","python","Script will not start","IndentationError: unexpected indent","Normalized tabs to spaces","2025-10"),
 ("H-122","recursion","python","Tree walker crashes","RecursionError: maximum recursion depth exceeded","Added base case and visited set for cycles","2026-02"),
 ("H-123","encoding","python","CSV import crash","UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe9","Opened with encoding='latin-1' then normalized to utf-8","2026-04"),
]

STOP = set("the and for with that this from have not are was but you your into when after".split())
def toks(s): return [t for t in re.findall(r"[a-z_][a-z0-9_]{2,}", (s or "").lower()) if t not in STOP]

def normalize(err):
    s = (err or "").lower()
    s = re.sub(r"(/|[a-z]:\\)[^\s:'\"]+", "<path>", s)
    s = re.sub(r"'[^']*'|\"[^\"]*\"", "<str>", s)
    s = re.sub(r"0x[0-9a-f]+|\b\d+\b", "<n>", s)
    return re.sub(r"\s+", " ", s).strip()

def classify(inp):
    err = inp.get("error_message", ""); other = " ".join(inp.get(k, "") for k in ("title", "description", "code"))
    scores = {}
    for c, (_, rx, *_r) in CATS.items():
        s = 3 * len(re.findall(rx, err.lower())) + len(re.findall(rx, other.lower()))
        if s: scores[c] = s
    if not scores: return None, 0, []
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    return ranked[0][0], ranked[0][1], ranked

def fingerprint(inp, cat):
    err = inp.get("error_message", "")
    m = re.search(r"([A-Za-z_.]*(?:Error|Exception|Rejection))", err)
    etype = m.group(1).split(".")[-1] if m else "NoErrorType"
    sig = normalize(err) or normalize(inp.get("title", ""))
    h = hashlib.sha1((cat or "x" + sig).encode() + sig.encode()).hexdigest()
    lang = (inp.get("language") or "any").lower()
    return {"id": f"{lang[:3]}-{(cat or 'unk')[:4]}-{h[:6]}".upper(), "error_type": etype, "category": cat or "unknown",
            "signature": sig[:160], "language": lang, "hash": h, "bands": [int(h[i:i+2], 16) for i in range(0, 24, 2)]}

class Engine:
    def __init__(self, db="bugdna.db"):
        self.db = sqlite3.connect(db, check_same_thread=False)
        self.db.execute("create table if not exists h(id integer primary key, ts real, data text)")
        self.corpus = [dict(id=i, category=c, language=l, title=t, error=e, resolution=r, date=d,
                            tokens=toks(f"{t} {e} {r}")) for i, c, l, t, e, r, d in SEED]
        df = Counter(t for b in self.corpus for t in set(b["tokens"])); n = len(self.corpus)
        self.idf = {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df.items()}

    def vec(self, tk):
        c = Counter(tk); return {t: v * self.idf.get(t, 1.5) for t, v in c.items()}
    @staticmethod
    def cos(a, b):
        d = sum(v * b.get(t, 0) for t, v in a.items())
        na = math.sqrt(sum(v * v for v in a.values())); nb = math.sqrt(sum(v * v for v in b.values()))
        return d / (na * nb) if na and nb else 0.0

    def history(self, limit=12):
        rows = self.db.execute("select data from h order by id desc limit ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def analyze(self, inp):
        cat, strength, ranked = classify(inp)
        label, _, cause, fixes = CATS[cat] if cat else GENERIC
        fp = fingerprint(inp, cat)
        q = self.vec(toks(" ".join([inp.get("title", ""), inp.get("error_message", "") * 2, inp.get("description", ""), inp.get("code", "")[:600]])))
        lang = fp["language"]; sims = []
        for b in self.corpus:
            s = 0.6 * self.cos(q, self.vec(b["tokens"])) + (0.3 if cat and b["category"] == cat else 0) \
                + (0.1 if b["language"] == lang else 0)
            sims.append((min(s, 0.99), b))
        sims.sort(key=lambda x: -x[0]); top = [(s, b) for s, b in sims[:4] if s > 0.12]
        similar = [{"id": b["id"], "title": b["title"], "language": b["language"], "error": b["error"],
                    "resolution": b["resolution"], "date": b["date"], "category": b["category"], "similarity": round(s * 100)} for s, b in top]
        # recurring pattern across corpus + user's own past submissions
        past = [h for h in self.history(200) if h["fingerprint"]["category"] == fp["category"]]
        in_seed = [b for b in self.corpus if b["category"] == cat]
        total = len(in_seed) + len(past)
        langs = Counter([b["language"] for b in in_seed] + [h["fingerprint"]["language"] for h in past])
        same_fp = sum(1 for h in past if h["fingerprint"]["hash"] == fp["hash"])
        pattern = {"category": label, "occurrences": total, "same_fingerprint_seen": same_fp,
                   "languages": dict(langs.most_common(3)),
                   "summary": (f"{label} has appeared {total} times in the bug history" if cat else "No recurring family detected yet")
                              + (f"; this exact fingerprint was submitted {same_fp} time(s) before." if same_fp else ".")}
        signals = []
        if cat and ranked: signals = [CATS[c][0] for c, _ in ranked[:3]]
        if top: cause_text = f"{cause} The closest past case ({top[0][1]['id']}) was resolved by: {top[0][1]['resolution'].lower()}."
        else: cause_text = cause
        conf = 0.3 + (min(strength, 8) / 8) * 0.4 + (top[0][0] * 0.3 if top else 0) if cat else 0.25 + (top[0][0] * 0.2 if top else 0)
        conf = round(min(conf, 0.96), 2)
        out = {"overview": {"title": inp.get("title") or "Untitled bug", "language": lang, "environment": inp.get("environment", ""),
                            "category": label, "severity": "high" if cat in ("memory", "db_conn", "cors_auth", "async_race") else "medium",
                            "has_code": bool(inp.get("code"))},
               "fingerprint": fp, "similar_bugs": similar, "pattern": pattern,
               "root_cause": {"hypothesis": cause_text, "signals": signals},
               "recommendation": {"steps": fixes, "first_action": fixes[0]},
               "meta": {"confidence": conf, "matched_categories": signals, "corpus_size": len(self.corpus), "engine": "bugdna-v1 (rules + tf-idf)"}}
        self.db.execute("insert into h(ts,data) values(?,?)", (time.time(), json.dumps({"title": out["overview"]["title"], "fingerprint": fp, "confidence": conf, "category": label})))
        self.db.commit()
        return out
