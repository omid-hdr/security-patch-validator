# نمایش مرحله‌به‌مرحله

## ۱. کد را ببین

```bash
cat -n targets/name-length/base.c
```

بافر ۱۶ بایتی است؛ بیش از ۱۵ بایت رشته با بایت پایان جا نمی‌شود.

## ۲. ساخت و مقایسهٔ درست

```bash
python3 validate.py --patched correct --out artifacts/correct
echo $?
```

انتظار: PASS و کد ۰. اکنون چهار باینری متناظر ساخته شده‌اند.

## ۳. رفتار عادی و خطا

```bash
./artifacts/correct/base-sanitized Ali
./artifacts/correct/base-sanitized AAAAAAAAAAAAAAAA
```

اولی ۳ چاپ می‌کند. دومی stack-buffer-overflow در ASan نشان می‌دهد.

```bash
./artifacts/correct/patched-sanitized AAAAAAAAAAAAAAAA
echo $?
```

بدون گزارش خطای حافظه با خروج ۲ رد می‌شود.

## ۴. وصلهٔ ناقص

```bash
python3 validate.py --patched incomplete --out artifacts/incomplete
echo $?
./artifacts/incomplete/patched-sanitized AAAAAAAAAAAAAAAAAAAA
echo $?
./artifacts/incomplete/patched-sanitized AAAAAAAAAAAAAAAA
```

اعتبارسنج کد ۱۰ می‌دهد؛ هدف ورودی ۲۰ حرفی را با خروج ۲ رد می‌کند ولی ۱۶ حرفی هنوز سرریز دارد.

## ۵. خرابی عملکرد

```bash
python3 validate.py --patched regression --out artifacts/regression
echo $?
./artifacts/regression/base-sanitized ABCDEFGH
./artifacts/regression/patched-sanitized ABCDEFGH
echo $?
```

اعتبارسنج کد ۲۰ می‌دهد؛ پایه ۸ چاپ می‌کند ولی وصله ورودی معتبر را با خروج ۲ رد می‌کند.

## ۶. کوچک‌سازی و Diff

```bash
wc -c artifacts/correct/finding-1/original.bin artifacts/correct/finding-1/minimized.bin
cat artifacts/correct/finding-1/patch.diff
less artifacts/correct/report.json
```

انتظار: ۲۰ بایت اولیه و ۱۶ بایت کوچک‌شده. در JSON سه replay، امضای خطا، ارتباط تابع و هانک Diff را ببین.

## ۷. بازتولید مستقل

```bash
cp -r artifacts/correct/finding-1/bundle /tmp/patchlab-reproducer
cd /tmp/patchlab-reproducer
python3 replay.py
```

خطای نسخهٔ پایه را دوباره نشان می‌دهد. برای بازگشت به مخزن مسیر خودت را وارد کن.

## ۸. اجرای پایپ‌لاین

```bash
python3 scripts/acceptance.py
```

همهٔ سناریوها شامل وصله‌های ندیده و خطاهای ساخت/پیکربندی بررسی می‌شوند.
`artifacts/acceptance/summary.json` جدول نتیجه‌هاست.
اجرای دوباره corpus تولیدشده در `regressions/name-length/` را خودکار بارگذاری می‌کند.
