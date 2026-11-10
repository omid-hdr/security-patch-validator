# TARGETS.md — نقش ۱: مهندسی هدف و سناریو

این سند خروجی نقش ۱ از پروژه اعتبارسنجی خودکار وصله‌های امنیتی است. دو هدف بررسی می‌شود:

1. **`name-length`** (آموزشی، تک‌فایلی C) — پیش‌تر در مخزن موجود است.
2. **`editorconfig`** (کتابخانه واقعی C، چندفایلی CMake) — این سند عمدتاً به این هدف می‌پردازد.

هر هدف دارای چهار نسخه است: `base`, `correct`, `incomplete`, `regression`. برای هدف دوم، دو PoC امنیتی و یک مجموعه آزمون عملکردی بر مبنای [`editorconfig-core-test`](https://github.com/editorconfig/editorconfig-core-test) رسمی تهیه شده است.

> **یادآور:** انتخاب این هدف نیازمند تأیید مدرس در مرحله طراحی است. این سند معیارهای داوری مستقل را مشخص می‌کند تا آن تأیید بر شواهد عینی استوار باشد.

---

## ۱. چرا editorconfig-core-c؟

| معیار PDF | وضعیت editorconfig-core-c |
|---|---|
| کتابخانه واقعی، غیرآموزشی | بله — پروژه‌ای فعال در [github.com/editorconfig/editorconfig-core-c](https://github.com/editorconfig/editorconfig-core-c) |
| زبان C/C++، باینری ELF | بله — C با CMake، خروجی `bin/editorconfig` و `lib/libeditorconfig.so` |
| آسیب‌پذیری شناخته‌شده عمومی | بله — CVE-2023-0341 و CVE-2026-40489 (GHSA-97xg-vrcq-254h) |
| وصله عمومی موجود | بله — کامیت [`5159be8`](https://github.com/editorconfig/editorconfig-core-c/commit/5159be88ad50641d9843289adda791ba300421ff) |
| آزمون مرجع مستقل | بله — مخزن [`editorconfig-core-test`](https://github.com/editorconfig/editorconfig-core-test) |
| ورودی از طریق فایل/argv/stdin | بله — CLI یک مسیر فایل به‌عنوان argv می‌گیرد |

---

## ۲. آسیب‌پذیری و محل آن

**CVE:** `CVE-2026-40489` (تکمیل ناقص CVE-2023-0341)
**GHSA:** `GHSA-97xg-vrcq-254h`
**نسخه‌های آسیب‌پذیر:** `editorconfig-core-c ≤ 0.12.10`
**نسخهٔ وصله‌شده:** `0.12.11`

### محل دقیق در کد

فایل: `src/lib/ec_glob.c`
تابع: `ec_glob()`
خطوط: ۹۵–۱۰۰ (پیش از وصله)

```c
char l_pattern[2 * PATTERN_MAX];   // line 95 — buffer 8194 bytes (PATTERN_MAX = 4097)
// ...
strcpy(l_pattern, pattern);        // line 100 — بدون بررسی طول
```

CVE-2023-0341 (نسخهٔ 0.12.6) بافر مجاور `pcre_str` را با `pcre_str_end` محافظت کرد، اما `l_pattern` که در همان scope تعریف شده بود را بدون کنترل گذاشت. وصلهٔ رسمی (کامیت 5159be8):

```c
size_t pattern_len = strlen(pattern);
if (pattern_len >= sizeof(l_pattern))   // رد طول ≥ 8194
    return -1;
memcpy(l_pattern, pattern, pattern_len + 1);  // کپی با طول کنترل‌شده
```

### نحوه ساخت pattern از سوی فراخواننده

`src/lib/editorconfig.c:239-242` (`ini_handler`):

```c
pattern = malloc(
    strlen(editorconfig_file_dir) * 2 +   // * 2 برای escape کاراکترهای خاص
    sizeof("**/") +
    strlen(section)
);
```

طول نهایی pattern = `escaped_dir + 3 + section_length` که در آن:

- `escaped_dir = dir_length + special_count`
- `special_count` تعداد کاراکترهای escape‌شونده در مسیر دایرکتوری است (`?[]\*-{},` — ۹ کاراکتر طبق `ec_glob.c:43`)
- `section_length` طول نام section در فایل `.editorconfig` (حداکثر `MAX_SECTION_NAME = 4096`)

**محاسبه سرریز نسخهٔ اصلی PoC (PoC-A):**

| ورودی | مقدار |
|---|---|
| طول دایرکتوری | 4070 |
| کاراکترهای خاص | 32 |
| طول escaped | 4102 |
| طول section | 4096 |
| **طول pattern** | **4102 + 3 + 4096 = 8201** |
| اندازهٔ بافر | 8194 |
| **سرریز** | **8201 − 8194 = 7 بایت** (+ 1 بایت NUL via strcpy → 8 بایت عملی) |

---

## ۳. چهار نسخه

### ۳.۱ مبنا و کامیت‌ها

| نسخه | مبنا | تغییر |
|---|---|---|
| `base`     | کامیت `b4724e4` (parent کامیت وصله) | سورس رسمی پیش از وصله |
| `correct`  | همان `base` | اعمال وصلهٔ رسمی `5159be8` (معادل `>=` + `memcpy`) |
| `incomplete` | همان `base` | اعمال وصله اما با `>` به‌جای `>=` (off-by-one) |
| `regression` | همان `base` | اعمال وصلهٔ رسمی + یک guard جدید که هر pattern حاوی `{` را رد می‌کند |

### ۳.۲ تفاوت‌های کد (دقیق)

**`base` → `correct`** (وصلهٔ رسمی):
```diff
+    size_t                    pattern_len = strlen(pattern);
-    strcpy(l_pattern, pattern);
+    if (pattern_len >= sizeof(l_pattern))
+        return -1;
+    memcpy(l_pattern, pattern, pattern_len + 1);
```

**`correct` → `incomplete`** (یک کاراکتر):
```diff
-    if (pattern_len >= sizeof(l_pattern))
+    if (pattern_len > sizeof(l_pattern))
```
نتیجه: pattern با طول دقیقاً `sizeof(l_pattern) = 8194` پذیرفته می‌شود؛ `memcpy` سپس `8194 + 1 = 8195` بایت می‌نویسد → ۱-بایت سرریز.

**`correct` → `regression`** (افزودن یک guard بعد از memcpy):
```c
+    if (strchr(l_pattern, '{') != NULL)
+        return -1;
```
نتیجه: bounds check حفظ می‌شود (امنیت دارد)، اما هر pattern حاوی `{` رد می‌شود → شکستن [brace alternation معتبر](https://spec.editorconfig.org/#glob-patterns) طبق spec.

### ۳.۳ رفتار مورد انتظار هر نسخه

| نسخه | PoC-A (8201B) | PoC-B (8194B) | آزمون عملکردی brace |
|---|---|---|---|
| `base`       | **سرریز** (strcpy 8202B → 8B سرریز) | **سرریز** (strcpy 8195B → 1B سرریز) | موفق (طبق spec) |
| `correct`    | رد می‌شود (`>=` 8194 → -1) | رد می‌شود | موفق |
| `incomplete` | رد می‌شود (`>` 8194 ⇒ 8201>8194 → -1) | **سرریز** (`>` 8194 ⇒ 8194>8194 نادرست → memcpy 8195B → 1B سرریز) | موفق |
| `regression` | رد می‌شود | رد می‌شود | **شکست** (pattern حاوی `{` رد می‌شود) |

---

## ۴. PoCهای امنیتی

هر دو PoC ساختار یکسان دارند: یک درخت دایرکتوری عمیق با کاراکترهای خاص + یک فایل `.editorconfig` با section طولانی + یک فایل trigger.

### ۴.۱ PoC-A (نسخهٔ اصلی GHSA، 7-byte سرریز)

```
pattern_total = 8201   (overflow 7 bytes via strcpy → 8 with NUL)
```

ساختار:
- ۱۵ کامپوننت از `'a' * 250 + "{x}"` (هر کدام ۲۵۳ کاراکتر و ۲ special)
- یک tail از `'a'` برای رسیدن به طول دقیق
- `.editorconfig` با section name ۴۰۹۶ کاراکتری

### ۴.۲ PoC-B (bypass برای وصلهٔ ناقص، 1-byte سرریز)

```
pattern_total = 8194   (exactly sizeof(l_pattern); +1 NUL → 1-byte overflow)
```

ساختار مشابه PoC-A اما با تنظیم دقیق طول‌ها برای رسیدن به `8194` بایت.

### ۴.۳ بازتولید

```bash
cd targets/editorconfig
python3 scripts/make_poc.py --root poc-trees/A --variant A
python3 scripts/make_poc.py --root poc-trees/B --variant B
TRIGGER_A=$(python3 -c "import os; [print(os.path.join(r,f)) for r,_,fs in os.walk('poc-trees/A') for f in fs if f=='trigger.py']" | head -1)
TRIGGER_B=$(python3 -c "import os; [print(os.path.join(r,f)) for r,_,fs in os.walk('poc-trees/B') for f in fs if f=='trigger.py']" | head -1)
# اجرا روی نسخهٔ پایه (باید کرش کند)
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 LD_LIBRARY_PATH=base/build-asan/lib \
  base/build-asan/bin/editorconfig "$TRIGGER_A"
echo "exit=$?"  # انتظار: 134 (SIGABRT) با گزارش AddressSanitizer
```

### ۴.۴ تأیید دستی با ASan

شواهد کامل در `evidence/<version>/<build>/<test-id>.log`. نمونه:

```
$ base/build-asan/bin/editorconfig ".../trigger.py"
==4906==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fa05ae04192
WRITE of size 8202 at 0x7fa05ae04192 thread T0
    #0 0x... in strcpy .../asan/asan_interceptors.cpp:563
    #1 0x... in ec_glob .../targets/editorconfig/base/src/lib/ec_glob.c:100
    #2 0x... in ini_handler .../editorconfig.c:268
    ...
    [8592, 16786) 'l_pattern' (line 95) <== Memory access at offset 16786 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow .../ec_glob.c:100 in strcpy
```

---

## ۵. آزمون‌های عملکردی (Oracle مستقل)

### ۵.۱ مرجع

[مخزن رسمی editorconfig-core-test](https://github.com/editorconfig/editorconfig-core-test) با آزمون‌های glob (braces.in، star.in، star_star.in، brackets.in، question.in). این فایل‌ها به `tests/official-glob/` کپی شده‌اند.

### ۵.۲ معیار عملکرد (Oracle)

معیار: خروجی editorconfig CLI باید با رفتار مستندشده در [spec.editorconfig.org](https://spec.editorconfig.org/) مطابقت داشته باشد. به طور خاص:
- الگوی `*.{py,js,html}` باید با `foo.py` مطابقت داشته باشد → `choice=true`
- الگوی `a{b,c,}.d` باید با `ab.d` مطابقت داشته باشد → `empty=word`

این معیار از خروجی نسخهٔ وصله‌شده به‌تنهایی استخراج نمی‌شود (طبق الزام PDF).

### ۵.۳ آزمون رگرسیون (برای نسخهٔ regression)

الگوی `[{foo,bar}.py]` در `func-trees/brace/.editorconfig` یک الگوی معتبر EditorConfig است. انتظار:
- `base`, `correct`, `incomplete`: خروجی `indent_style=space` (موفق)
- `regression`: خروجی خالی (شکست — چون `ec_glob` pattern را به دلیل وجود `{` رد می‌کند)

اجرای آزمون:

```bash
python3 tests/run_official_glob.py \
    --binary <version>/build-normal/bin/editorconfig \
    --library <version>/build-normal/lib \
    --verbose
```

---

## ۶. وصله‌های ندیده (برای جلسهٔ دفاع)

سه وصلهٔ جایگزین در `unseen-patches/`:

| فایل | رویکرد | انتظار ابزار |
|---|---|---|
| `unseen-1-snprintf.patch` | `snprintf` به‌جای `memcpy` (با bounds check یکسان) | PASS — امن و عملکرد صحیح |
| `unseen-2-strncpy.patch` | `strncpy` + NUL صریح (با bounds check یکسان) | PASS — امن و عملکرد صحیح |
| `unseen-3-conservative.patch` | رد pattern > 8000 بایت (سخت‌گیرانه‌تر از رسمی) | PASS — امن، اما برخی patternهای معتبر بین 8001-8193 بایت را رد می‌کند |

هر وصله به‌صورت یک `git diff` معتبر است که با `git apply` روی `base/` اعمال می‌شود. ابزار باید:
1. بیلد عادی + ابزارگذاری‌شده بسازد.
2. PoC-A و PoC-B را روی هر دو نسخه اجرا کند.
3. با استفاده از همان شواهد `correct`، خروجی `PASS` (کد ۰) بدهد.

اجزای ندیده نباید بر اساس نام فایل یا شناسهٔ CVE تصمیم بگیرند — فقط بر اساس بازتولید PoCها و آزمون‌های عملکردی.

---

## ۷. خلاصهٔ شواهد

جدول کامل در `evidence/` — خلاصهٔ اجرا روی ۸ باینری (۴ نسخه × ۲ build):

| نسخه | Build | PoC-A | PoC-B | func-brace-match |
|---|---|---|---|---|
| `base`       | normal | rc=134 (stack smashing) | rc=0 (سرریز خاموش) | `indent_style=space` ✓ |
| `base`       | asan   | rc=134 (ASan overflow) | rc=134 (ASan overflow) | `indent_style=space` ✓ |
| `correct`    | any    | rc=0 | rc=0 | `indent_style=space` ✓ |
| `incomplete` | normal | rc=0 | rc=0 | `indent_style=space` ✓ |
| `incomplete` | asan   | rc=0 | **rc=134 (ASan overflow)** ✓ | `indent_style=space` ✓ |
| `regression` | any    | rc=0 | rc=0 | **خروجی خالی ✗** |

نکته: `base/normal/PoC-B` با rc=0 خارج می‌شود چون سرریز ۱-بایتی خاموش است و stack canary آن را تشخیص نمی‌دهد؛ فقط ASan آن را در `build-asan` شناسایی می‌کند. این تفاوت build عادی و ابزارگذاری‌شده را — که طبق PDF الزام است — روشن نشان می‌دهد.

---

## ۸. ساختار دایرکتوری

```
targets/editorconfig/
├── base/              ← سورس editorconfig-core-c در کامیت b4724e4 (پایهٔ آسیب‌پذیر)
│   ├── build-normal/  ← بیلد عادی (gcc, no sanitizer)
│   └── build-asan/    ← بیلد ابزارگذاری‌شده (ASan/UBSan)
├── correct/           ← همان base + وصلهٔ رسمی 5159be8
├── incomplete/        ← همان correct اما با `>` به‌جای `>=` (off-by-one)
├── regression/        ← همان correct + guard ضد `{`
├── scripts/
│   ├── make_poc.py          ← ساخت درخت PoC (variant A یا B)
│   ├── build_all.sh         ← بیلد هر هشت باینری
│   ├── run_all.sh           ← اجرای همهٔ PoCها و آزمون‌ها روی هر هشت باینری
│   └── summarize_evidence.py ← خروجی جدول خلاصه
├── tests/
│   ├── official-glob/       ← فایل‌های .in از editorconfig-core-test رسمی
│   └── run_official_glob.py ← اجرای آزمون‌های عملکردی رسمی
├── poc-trees/               ← درخت‌های PoC (تولیدشده، در .gitignore)
├── func-trees/brace/        ← درخت آزمون رگرسیون brace
├── unseen-patches/          ← سه وصلهٔ ندیده برای جلسهٔ دفاع
├── evidence/                ← خروجی هر اجرا (log)
└── TARGETS.md               ← این فایل
```

---

## ۹. پیکربندی نمونه (برای نقش ۴)

نقش ۴ مالک شمای کلی config است. نقش ۱ فقط محتوا را تحویل می‌دهد. نمونهٔ `configs/editorconfig.json` (مفهومی، شمای نهایی با نقش ۴ هماهنگ شود):

```json
{
  "name": "editorconfig",
  "sources": {
    "base": "targets/editorconfig/base",
    "correct": "targets/editorconfig/correct",
    "incomplete": "targets/editorconfig/incomplete",
    "regression": "targets/editorconfig/regression"
  },
  "build": {
    "type": "cmake",
    "source_dir": "{source}",
    "build_dir": "{source}/build-{flavor}",
    "normal": "cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-g -O0 -fno-pie -no-pie -fstack-protector-strong -Wl,-z,relro,-z,now' {source} -B {build_dir} && make -C {build_dir} editorconfig_bin",
    "sanitized": "cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-g -O0 -fno-pie -no-pie -fsanitize=address,undefined -U_FORTIFY_SOURCE' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined -fno-pie -no-pie' -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address,undefined' {source} -B {build_dir} && make -C {build_dir} editorconfig_bin"
  },
  "binary": {
    "normal": "{build_dir}/bin/editorconfig",
    "sanitized": "{build_dir}/bin/editorconfig"
  },
  "library_path": "{build_dir}/lib",
  "input_mode": "argv",
  "run": {
    "argv": ["{binary}", "{input}"],
    "mode": "argv",
    "timeout": 30,
    "replays": 3,
    "env": {"LD_LIBRARY_PATH": "{library_path}"}
  },
  "expected_error": {
    "type": "stack-buffer-overflow",
    "function": "ec_glob",
    "file": "src/lib/ec_glob.c",
    "line": 100
  },
  "security_tests": [
    {"id": "poc-A-original", "poc_script": "scripts/make_poc.py --variant A", "expected_exit": "abort_signal", "expected_sanitizer": "AddressSanitizer"},
    {"id": "poc-B-bypass",   "poc_script": "scripts/make_poc.py --variant B", "expected_exit": "abort_signal", "expected_sanitizer": "AddressSanitizer"}
  ],
  "functional_tests": [
    {"id": "brace-match-foo",  "tree": "func-trees/brace", "trigger": "foo.py", "expected_stdout": "indent_style=space\n"},
    {"id": "brace-nomatch-baz", "tree": "func-trees/brace", "trigger": "baz.py", "expected_stdout": ""}
  ],
  "functional_oracle": "tests/run_official_glob.py",
  "hardening_required": {"nx": true, "pie": false, "relro": "full", "canary_evidence": true}
}
```

> **توجه برای نقش ۴:** این یک شمای مفهومی است. نقش ۴ باید شمای کلی `configs/name-length.json` را به‌گونه‌ای تعمیم دهد که هم تک‌فایلی (name-length) و هم چندفایلی (editorconfig) را پشتیبانی کند. در حالت چندفایلی، فیلدهای `build.type=cmake` و `build.source_dir` و `library_path` اضافه می‌شوند؛ PoC نیز به‌جای `input` ثابت از `poc_script` می‌آید.

---

## ۱۰. الزامات تأیید نهایی

| الزام PDF | وضعیت |
|---|---|
| بازتولید آسیب‌پذیری با ASan در نسخهٔ base | ✓ (`evidence/base/asan/poc-A-original.log` و `poc-B-bypass.log`) |
| رفع آسیب‌پذیری در نسخهٔ correct | ✓ (rc=0 روی هر دو PoC) |
| PoC دورزننده برای وصلهٔ ناقص | ✓ (PoC-B روی `incomplete/asan` کرش می‌کند) |
| آزمون عملکردی معتبر که در regression شکست می‌خورد | ✓ (brace test روی `regression` خالی می‌ماند) |
| تفکیک build عادی و ابزارگذاری‌شده | ✓ (PoC-B فقط در build-asan شناسایی می‌شود) |
| مستقل از نام فایل/CVE | ✓ (PoC از قرارداد CLI بهره می‌برد، نه از شناسه) |
| وصله‌های ندیده | ✓ (سه وصلهٔ آماده) |
| مرجع عملکرد مستقل | ✓ (editorconfig-core-test رسمی) |
| بازتولید مستقل روی اوبونتو | کاربر باید `git pull && targets/editorconfig/scripts/build_all.sh && run_all.sh` را اجرا کند |

---

## ۱۱. محدودیت‌ها

- پوشش آزمون‌ها محدود است — PASS اثبات نبود تمام آسیب‌پذیری‌ها نیست.
- ابزار مبتنی بر PoC است؛ fuzzing یا تست‌های فراتر از PoCها جزو نقش ۱ نیست.
- PoC وابسته به `PATH_MAX = 4096` و `MAX_SECTION_NAME = 4096` روی Linux x86_64 است. در سیستم‌عامل‌های دیگر ممکن است نیاز به تنظیم مجدد باشد.
- وصلهٔ regression فقط brace alternation را می‌شکند؛ سایر رفتارهای معتبر (مثل `**` یا `[...]`) سالم هستند.
- وصله‌های ندیده با `git apply` روی `base/` اعمال می‌شوند؛ ابزار باید بتواند با `--patched-source` یک درخت سورس را ارزیابی کند (این قابلیت در نقش ۴ توسعه داده می‌شود).
