# INTERFACES.md — امضاهای تابع عمومی هر ماژول

این سند مرجع رابط‌های عمومی هر ماژول است (طبق الزام نقش‌ها در docx تقسیم وظایف).
تمام این امضاها در کد موجود (`patchlab/*.py`) پیاده‌سازی شده‌اند.

## نقش ۲: هسته اجرا و آزمون پویا

### `patchlab/runner.py`

```python
# محیط کنترل‌شده برای subprocess (فقط تنظیمات مؤثر، بدون secrets کاربر)
def controlled_env(extra_env: dict | None = None,
                   extra_path: list | None = None) -> dict

# اجرای یک فرمان با محدودیت منابع و ایزولاسیون
# خروجی: dict با argv, cwd, exit_code, signal, stdout, stderr,
#         timed_out, error_type, detection_mechanism, frames, signature, abnormal
def execute(argv: list, cwd: Path, timeout: int = 15,
           input_bytes: bytes | None = None,
           extra_env: dict | None = None,
           extra_path: list | None = None) -> dict

# نسخهٔ typed از execute()
def run_to_result(argv: list, cwd: Path, timeout: int = 15,
                  input_bytes: bytes | None = None,
                  extra_env: dict | None = None,
                  extra_path: list | None = None) -> RunResult

# طبقه‌بندی خروجی sanitizer (ASan/UBSan/stack-canary/FORTIFY/os-signal)
def classify(stderr: str, sig: int | None = None,
             timed_out: bool = False) -> dict

# مقایسهٔ امضای خطا (dict یا ErrorSignature)
def same_error(a, b) -> bool

# محاسبهٔ SHA256
def sha256(path) -> str

@dataclass
class RunResult:
    argv: list
    cwd: str
    exit_code: int
    signal: int | None
    stdout: str
    stderr: str
    timed_out: bool
    sanitizer_detected: bool
    error_type: str | None
    error_location: str | None
    crashed: bool

@dataclass
class ErrorSignature:
    error_type: str
    functions: list
    file: str | None
    line: int | None
    def matches(self, other: "ErrorSignature") -> bool
```

### `patchlab/builder.py` (نقش ۲ — Build Manager)

```python
# بیلد تک‌فایلی (name-length): gcc {source} -o {binary}
def build_single_file(source: Path, binary: Path,
                      command_template: list, cwd: Path,
                      timeout: int = 60) -> dict

# بیلد cmake چندفایلی (editorconfig): cmake + make
def build_cmake(source_dir: Path, build_dir: Path, flavor: str,
                cmake_flags: list, make_targets: list,
                cwd: Path, extra_path: list | None = None,
                timeout: int = 120) -> dict

# مکان‌یابی باینری و کتابخانهٔ ساخته‌شده در build_dir
def locate_binary(build_dir: Path, name: str = "editorconfig") -> Path | None
def locate_library(build_dir: Path, name: str = "libeditorconfig") -> Path | None
def remove_build_dir(build_dir: Path) -> None
```

## نقش ۳: تحلیل و شواهد

### `patchlab/evidence.py`

```python
# کوچک‌سازی ddmin (byte-level)
def minimize(data: bytes, predicate, max_runs: int = 150) -> tuple[bytes, dict]

# کوچک‌سازی ساختاری برای PoC دایرکتوری‌محور (variant-based)
def minimize_poc_tree(make_poc_callable, predicate, *,
                      variants: list | None = None,
                      max_runs: int = 20) -> tuple

# بررسی binary hardening (NX, PIE, RELRO, Canary)
def hardening(binary: Path) -> dict

# تطبیق Diff — تک‌فایلی
def correlate(base_source: Path, patched_source: Path,
              base_frames: list, patched_frames: list,
              comparisons: list) -> dict

# تطبیق Diff — چندفایلی (پروژهٔ کامل)
def project_correlate(base_dir: Path, patched_dir: Path,
                      base_frames: list, patched_frames: list,
                      comparisons: list,
                      exclude_patterns: list | None = None) -> dict

# بستهٔ بازتولید — تک‌فایلی
def bundle(destination: Path, source: Path, binary: Path,
           input_bytes: bytes, build_command: list,
           result: dict, metadata: dict, mode: str, run_argv: list) -> None

# بستهٔ بازتولید — چندفایلی (CMake)
def project_bundle(destination: Path, source_dir: Path, binary: Path,
                   library: Path | None, trigger_file: Path,
                   build_metadata: dict, run_metadata: dict,
                   *, exclude_patterns: list | None = None) -> None
```

## نقش ۴: ارکستراسیون و یکپارچه‌سازی

### `patchlab/validate.py`

```python
# بارگذاری و اعتبارسنجی config (شمای یکپارچه: single-file + cmake)
def load_config(path: str | Path) -> dict

# آماده‌سازی دادهٔ آزمون (input/input_repeat/hex/poc_script)
def data_for(test: dict) -> bytes
def prepare_poc(test: dict, output_dir: Path) -> tuple[bytes, Path | None]

# oracle (بررسی مطابقت با انتظار)
def oracle(result: dict, case: dict) -> bool

# تصمیم‌گیری exit code طبق اولویت PDF
def decide(flags: dict) -> int

# پایپ‌لاین اصلی اعتبارسنجی
def validate(config_path: str | Path, patched: str, output: str | Path,
             base: str = "base",
             patched_source: str | None = None,
             base_source: str | None = None,
             extra_path: list | None = None) -> int

# رابط خط فرمان
def main() -> int
```

### `scripts/acceptance.py` (نقش ۴ — آزمون پذیرش name-length)

```python
def run(name: str, expected: int, extra: tuple = ()) -> tuple[dict, Path]
def main() -> None
```

### `scripts/acceptance_editorconfig.py` (نقش ۴ — آزمون پذیرش editorconfig)

```python
def run(name: str, expected: int, extra: tuple = ()) -> tuple[dict, Path]
def main() -> None
```

## شمای پیکربندی (Config Schema)

یکپارچه برای هر دو هدف. شمای `configs/name-length.json` و `configs/editorconfig.json`
از همین قالب پیروی می‌کنند.

### فیلدهای مشترک

| فیلد | نوع | الزامی | توضیح |
|---|---|---|---|
| `name` | string | بله | شناسهٔ هدف |
| `build_type` | `"single-file"` یا `"cmake"` | خیر (پیش‌فرض: `single-file`) | شکل بیلد |
| `sources` | dict | بله | مسیرهای `base`, `correct`, `incomplete`, `regression` |
| `builds` | dict | بله | بیلد `normal` و `sanitized` |
| `run` | dict | بله | argv, mode, timeout, replays |
| `expected_error` | dict | بله | type و function |
| `security_tests` | list | بله | فهرست آزمون‌های امنیتی |
| `functional_tests` | list | بله | فهرست آزمون‌های عملکردی |
| `hardening_required` | dict | بله | nx, pie, relro, canary_evidence |

### شکل بیلد

**`build_type: "single-file"`** (مثل name-length):

```json
"builds": {
  "normal":    ["gcc", "-std=c11", "{source}", "-o", "{binary}"],
  "sanitized": ["gcc", "-std=c11", "-fsanitize=address,undefined", "{source}", "-o", "{binary}"]
}
```

**`build_type: "cmake"`** (مثل editorconfig):

```json
"builds": {
  "normal": {
    "cmake_flags": ["-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_C_FLAGS=..."],
    "make_targets": ["editorconfig_bin"]
  },
  "sanitized": {
    "cmake_flags": ["-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_C_FLAGS=... -fsanitize=address,undefined"],
    "make_targets": ["editorconfig_bin"]
  },
  "binary_name": "editorconfig"
}
```

### شکل آزمون

آزمون‌های امنیتی می‌توانند یکی از سه شکل داشته باشند:

```json
// شکل ۱: ورودی متنی ساده
{"id": "short", "input": "Ali", "expected_exit": 0, "expected_stdout": "3\n"}

// شکل ۲: ورودی تکراری (برای طول‌های بزرگ)
{"id": "very-long", "input_repeat": ["B", 256], "expected_exit": 2, "expected_stdout": ""}

// شکل ۳: PoC پویا (دایرکتوری‌محور)
{
  "id": "poc-A-original",
  "poc_script": "python3 targets/editorconfig/scripts/make_poc.py --root $POC_ROOT --variant A",
  "trigger_finder": "python3 -c \"import os;[print(os.path.join(r,f)) for r,_,fs in os.walk('$POC_ROOT') for f in fs if f=='trigger.py']\" | head -1",
  "expected_exit": 134,
  "expected_stdout": ""
}
```

آزمون‌های عملکردی می‌توانند `expected_stdout` یا `expected_stdout_contains` داشته باشند.
