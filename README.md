# اعتبارسنجی خودکار وصلهٔ امنیتی — چند هدف

این مخزن یک پیاده‌سازی اجرایی برای پروژهٔ اعتبارسنجی خودکار وصله‌های امنیتی است.
دو هدف بررسی می‌شود:

| هدف | نوع | آسیب‌پذیری | شکل بیلد | config |
|---|---|---|---|---|
| `name-length` | آموزشی، تک‌فایلی C | سرریز بافر `strcpy` | `gcc <file>.c` | `configs/name-length.json` |
| `editorconfig` | واقعی، کتابخانهٔ C (CVE-2026-40489) | سرریز `l_pattern` در `ec_glob` | `cmake + make` | `configs/editorconfig.json` |

هر هدف دارای چهار نسخه است: `base`، `correct`، `incomplete`، `regression`.
برای `editorconfig`، سه وصلهٔ ندیده نیز در `targets/editorconfig/unseen-patches/` آمادهٔ جلسهٔ دفاع است.

## اجرای سریع در اوبونتو

پیش‌نیازها: Linux x86_64، Python 3.10+، GCC، Git و binutils/readelf. برای هدف `editorconfig` نیاز به cmake و libpcre2-dev هم هست. وابستگی Python خارجی ندارد.

```bash
sudo apt-get update
sudo apt-get install -y gcc binutils python3 git cmake make libpcre2-dev
git clone https://github.com/omid-hdr/security-patch-validator.git
cd security-patch-validator

# آزمون پذیرش هر دو هدف:
python3 scripts/acceptance.py             # name-length
python3 scripts/acceptance_editorconfig.py  # editorconfig
```

در پایان باید `ALL ACCEPTANCE CHECKS PASSED` و `EDITORCONFIG ACCEPTANCE CHECKS PASSED` ببینید.
خروجی‌ها در `artifacts/acceptance/` و `artifacts/acceptance-editorconfig/` هستند و خودکار وارد Git نمی‌شوند.

## یک مقایسهٔ واقعی برای هر هدف

```bash
# هدف name-length:
python3 validate.py --patched correct --out artifacts/nl-correct;     echo $?
python3 validate.py --patched incomplete --out artifacts/nl-incomplete; echo $?
python3 validate.py --patched regression --out artifacts/nl-regression; echo $?
# کدهای مورد انتظار: 0، 10، 20

# هدف editorconfig:
python3 validate.py --config configs/editorconfig.json --patched correct --out artifacts/ec-correct;     echo $?
python3 validate.py --config configs/editorconfig.json --patched incomplete --out artifacts/ec-incomplete; echo $?
python3 validate.py --config configs/editorconfig.json --patched regression --out artifacts/ec-regression; echo $?
# کدهای مورد انتظار: 0، 10، 20
```

برچسب `--patched` فقط کلید منبع در پیکربندی را انتخاب می‌کند؛ تعیین‌کنندهٔ نتیجه نیست.
برای وصلهٔ نام تازه (تک‌فایلی):
```bash
python3 validate.py --patched-source /path/to/unseen.c --out artifacts/unseen
```

| کد | معنی |
|---|---|
| 0 | خطای پایه بازتولید شده؛ در وصله مشاهده نشده؛ آزمون‌های عملکردی و بررسی‌های الزامی موفق‌اند |
| 10 | خطای امنیتی/حافظهٔ تأییدشده باقی مانده یا تازه مشاهده شده است |
| 20 | آزمون عملکردی مطابق مرجع روی پایه موفق و روی وصله ناموفق است |
| 30 | خطای ساخت، پیکربندی، محیط یا اجرای ابزار |
| 40 | شواهد ناکافی، بازتولیدناپذیری یا بررسی ناقص |

اولویت هم‌زمانی: `30 > 40 > 20 > 10 > 0`. وضعیت امنیت و عملکرد جداگانه در JSON حفظ می‌شود.
کد خروج **برنامهٔ هدف** با کد خروج اعتبارسنج فرق دارد؛ خروج ۲ از هدف برای نام بیش‌ازحد بلند صحیح است.

## قرارداد هدف، مستقل از وصله (name-length)

برنامه دقیقاً یک آرگومان می‌گیرد. طول **بایتی UTF-8** از صفر تا ۱۵ معتبر است: خروج ۰ و چاپ طول به‌اضافهٔ newline.
طول ۱۶ و بیشتر نامعتبر است: خروج ۲ بدون خروجی. نبود آرگومان/آرگومان اضافه: خروج ۱.
آرگومان سیستم‌عامل بایت NUL داخلی ندارد؛ برای چنین ورودی‌ای حالت file یا stdin لازم است.
این قرارداد از ظرفیت ثابت بافر و رابط هدف تعیین شده، نه از خروجی نسخهٔ وصله‌شده یا نظر مدل زبانی.

| فایل | تغییر | انتظار |
|---|---|---|
| base.c | strcpy بدون کنترل | خطای حافظه با طول ۱۶ و بیشتر |
| correct.c | رد طول >= 16 | رفع خطا در آزمون‌ها و حفظ عملکرد |
| incomplete.c | رد طول > 16 | ورودی اولیهٔ ۲۰ رد می‌شود، ولی طول ۱۶ سرریز دارد |
| regression.c | رد طول >= 8 | خطا مهار می‌شود ولی نام‌های معتبر ۸ تا ۱۵ اشتباه رد می‌شوند |

هر چهار فایل در `targets/name-length/` هستند؛ هش منبع، هش باینری و commit مخزن در هر گزارش ثبت می‌شود.
برای نمایش تعاملی از [راهنمای قدم‌به‌قدم](docs/WALKTHROUGH.fa.md) استفاده کنید.

## پشت صحنه

1. بارگذاری JSON و ساخت بیلد عادی و ASan/UBSan برای هر دو نسخه با تنظیمات متناظر.
2. اجرای آزمون‌های معتبر، مرزی، نامعتبر و آزمون‌های رگرسیون ذخیره‌شده روی هر چهار ترکیب نسخه/بیلد.
3. ثبت stdout، stderr، سیگنال، timeout، روش تشخیص و stack trace؛ خروج غیرصفر به‌تنهایی خطای امنیتی نیست.
4. حداقل سه بازپخش؛ مقایسهٔ امضای خطا بر اساس نوع و زنجیرهٔ توابع، مستقل از آدرس و جابه‌جایی شمارهٔ خط.
5. کوچک‌سازی ddmin با حذف قطعه‌ها و بررسی حذف تک‌بایتی؛ سه بازپخش ورودی کوچک‌شده و اجرای آن روی هر دو نسخه/بیلد.
6. تولید خودکار corpus رگرسیون و بارگذاری آن در اجرای بعدی.
7. تولید Git Diff و تطبیق فریم پویا با تابع تغییرکرده؛ نبود شواهد، رابطهٔ نامشخص می‌دهد. هم‌بستگی ادعای اثبات علیت نیست.
8. تحلیل NX، PIE، سطوح RELRO و شواهد قناری از بیلد عادی؛ ثبت خروجی خام readelf و هشدار تغییر وضعیت.
9. تولید JSON، خلاصهٔ متنی و بستهٔ بازتولید مستقل.

## گزارش و بازتولید

```bash
cat artifacts/correct/summary.txt
less artifacts/correct/report.json
cat artifacts/correct/finding-1/patch.diff
python3 artifacts/correct/finding-1/bundle/replay.py
```

بستهٔ آخر خطا را روی **نسخهٔ پایه** بازتولید می‌کند؛ خروج غیرصفر و گزارش ASan در این دستور مورد انتظار است.
هر بسته شامل منبع، باینری Linux، ورودی کوچک‌شده، دستور ساخت، هش‌ها، محیط مؤثر، commit و replay.py است.
برای ساخت مجدد، داخل بسته دستور فهرست‌شده در `manifest.json` را اجرا کنید؛ همان ابزارهای ساخت لازم‌اند.
دستور بازپخش باینری ذخیره‌شده به وجود مخزن اصلی وابسته نیست؛ سازگاری glibc/معماری میزبان همچنان لازم است.

## CI روی همان اوبونتو

```bash
python3 scripts/acceptance.py
```

همین فرمان پایپ‌لاین محلی است و وابستگی به گیت‌هاب ندارد. برای محدودیت حافظه/تعداد فرایند با systemd کاربر:

```bash
systemd-run --user --wait --pipe --collect \
  --property=MemoryMax=1G --property=TasksMax=128 --property=RuntimeMaxSec=10min \
  --working-directory="$PWD" /usr/bin/python3 scripts/acceptance.py
```

محدودیت مستقیم اجرا شامل زمان، CPU، اندازهٔ فایل خروجی، تعداد فایل باز و غیرفعال‌کردن core dump است.
RLIMIT_AS برای ASan تنظیم نشده، چون ASan فضای آدرس مجازی بزرگی رزرو می‌کند. محدودیت حافظهٔ واقعی از cgroup/container می‌آید.
اجرای مستقیم جایگزین sandbox برای کد ناشناس نیست؛ این مخزن برای هدف‌های آموزشی مجاز و شناخته‌شده تهیه شده است.

## CI در GitHub Actions

فایل `.github/workflows/validate.yml` همان آزمون پذیرش را پس از push/PR و اجرای دستی روی Ubuntu اجرا می‌کند.
گزارش‌ها و بسته‌ها با `actions/upload-artifact` برای ۱۴ روز نگهداری می‌شوند.
سبزشدن CI یعنی ابزار وصلهٔ درست را پذیرفته **و وصله‌های خراب را مطابق انتظار رد کرده**.
انتشار سرویس یا وب‌سایت بخشی از این پروژه نیست؛ تحویل کد و پایپ‌لاین اعتبارسنج است.

## کانتینر اختیاری

```bash
docker build -t patchlab .
mkdir -p artifacts regressions
docker run --rm --user "$(id -u):$(id -g)" --network none --memory 1g --cpus 2 --pids-limit 128 \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  -v "$PWD/artifacts:/lab/artifacts" -v "$PWD/regressions:/lab/regressions" patchlab
```

کانتینر با کاربر غیرریشه اجرا می‌شود؛ پوشه‌های bind mount فقط خروجی و corpus هستند.
Docker در ماشین آموزشی فعلی نصب نیست؛ آزمون Docker باید جدا انجام شود. مسیر اصلی اجرای تأییدشده، همان اوبونتو است.

## همکاری تیمی

مخزن خصوصی است؛ دریافت توسط هم‌تیمی‌ها به دسترسی collaborator از مالک مخزن نیاز دارد.
نام کاربری هم‌تیمی‌ها در اختیار ابزار نیست و دعوتی خودکار ارسال نشده است.
هر نفر شاخهٔ خودش را بسازد و قبل از push آزمون پذیرش را اجرا کند.
فایل‌ها/کلیدهای SSH، اطلاعات ورود، محیط کامل کاربر و خروجی‌های موقت را commit نکنید.
تاریخچهٔ Git و خروجی منتسب به افراد، جای فهم کد و دفاع فردی را نمی‌گیرد.

## محدودیت‌های مشخص

- این مخزن فقط یک هدف آموزشی دارد؛ جایگزین هدف واقعی دوم پروژه نیست.
- تحلیل ارتباط Diff مبتنی بر توابع و stack trace است؛ تحلیل عمومی جریان داده یا اثبات علیت نیست.
- امضای خطا برای این هدف کوچک مناسب است؛ برای کدبیس بزرگ نیازمند دقیق‌سازی و تست بیشتر است.
- پوشش آزمون‌ها محدود است؛ PASS اثبات نبود تمام آسیب‌پذیری‌ها نیست.
- پروفایل آموزشی عمداً non-PIE است تا آزمایش ASan پایدار باشد؛ محافظت‌ها گزارش می‌شوند و این تنظیم توصیهٔ تولید نیست.
- نماد قناری، حفاظت تمام توابع و PIE، فعال‌بودن ASLR در محیط را اثبات نمی‌کند.
- کوچک‌سازی در بودجهٔ حداکثر ۱۵۰ اجرا انجام می‌شود؛ اتمام بودجه و وضعیت 1-minimal در گزارش مشخص است.
- برنامهٔ هدف یک فایل C است؛ build template و ورودی‌ها قابل تعویض‌اند؛ برای پروژهٔ چندفایلی باید دستور ساخت مناسب تعریف شود.

منابع ابزارها: [ASan در GCC](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)،
[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)،
[GitHub Actions](https://docs.github.com/en/actions).
