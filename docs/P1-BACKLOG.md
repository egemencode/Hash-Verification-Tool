# P1 Backlog

Bu turda (red-team P0 kapanışı ve ardından §3 CLI/klasör sözleşmesi) **kapsam
dışı** bırakılan, bağımsız denetimde tespit edilmiş maddeler. Hiçbiri güvenlik
kararlarını yanlış üretmiyor; hepsi kullanılabilirlik/tutarlılık sorunu.

> §3 turunda madde 3'ün çekirdek yarısı kapandı: `build_manifest_for_folder`
> ve `Verifier.verify` artık `cancel` yordamı alıyor, iptal edilen tarama ayrı
> bir `ScanState.CANCELLED` terminal olayı üretiyor ve hiçbir koşulda manifest
> olarak kaydedilmiyor. Eksik olan hâlâ **kullanıcıya görünür düğme**.

## 1. Ayarlar'da "API Anahtarını Kaldır" eylemi yok

`AppSettings.clear_api_key()` mevcut ve tek silme yolu bu — ancak Ayarlar
ekranında bunu çağıran bir düğme yok. Kullanıcı, alanı boşaltarak anahtarı
silemiyor: çözülemeyen bir token korunduğu için alan boş kaydedilse bile token
diskte kalıyor (bu, veri kaybını önlemek için bilinçli).

**Yapılacak:** Ayarlar > VirusTotal bölümüne "Anahtarı Kaldır" düğmesi; onay
sorusu; `clear_api_key()` + `save()`; sonuç durumunun ekranda gösterilmesi.

## 2. Menü dili ile Ayarlar dili iki ayrı state kullanıyor

`HashToolApp._settings` (ham dict) ve `AppSettings.language` ayrı ayrı
tutuluyor. Menüden dil değiştirilip ardından Ayarlar > Kaydet'e basılırsa,
Ayarlar ekranındaki draft (açılışta yüklenen dil) menüden yapılan seçimi geri
alıyor.

**Yapılacak:** Tek authoritative dil kaynağı; Ayarlar görünümü açıldığında
draft'ı canlı dilden tazelemek veya dili tamamen `AppSettings`'e taşımak.

## 3. ~~Kullanıcıya görünür "İptal" düğmesi yok~~ — Trust Check için KAPANDI

Trust Check ekranına İptal düğmesi eklendi (`gui/views/trust_check_view.py`).
`_controller.cancel()` çağırıyor (`shutdown()` **değil** — o denetleyiciyi
kalıcı olarak kapatır ve ekran bir daha tarama yapamaz), `_set_busy` ile tarama
sırasında etkin / boştayken pasif, işbirlikçi iptal için "İptal ediliyor…"
geçiş durumu gösteriyor. Terminal kart artık iptale özel öğüt veriyor
("Hazır olduğunuzda yeniden tarayabilirsiniz." — iptal eden kullanıcıya
"sorunu giderin" demek yanlıştı).

Testler: `tests/test_gui_cancel_button.py`, ikisi de
`tools/verify_fix_coverage.py` ile tutuluyor.

> **Kalan kısım — Gelişmiş sekmeleri (madde 9).** Hash / Verify / Report
> sekmelerinde hâlâ iptal yok.

## 4. Ayarlar'daki "Anahtarı Test Et" için ortak görev yöneticisi yok

`SettingsView._on_test` kendi thread'ini açıyor; `ScanController`'dan bağımsız.
Bu thread iptal edilemiyor, uygulama kapanışında beklenmiyor ve `after()`
callback'i `_poll_after_id` disiplinine tabi değil.

**Yapılacak:** Uygulama geneli tek görev yöneticisi (session kimliği, iptal,
bounded join, tek scheduler) ve Ayarlar test akışının ona bağlanması.

## 5. GUI'de imzalama akışı yok

`keygen` / `sign` / `--sign-key` yalnız CLI'da. GUI'den üretilen her manifest
imzasız; doğrularken `--allow-unsigned` karşılığı bir kabul adımı da yok, GUI
imzasız referansı sessizce kullanıyor.

**Yapılacak:** Gelişmiş > Hash sekmesine anahtar seçimi ve "Manifesti imzala";
Doğrula sekmesine güvenilen genel anahtar alanı; imzasız referans için CLI'daki
ile aynı bilinçli kabul adımı.

## 6. Uzun yol dayanıklılığı yalnız kaynak üzerinde doğrulandı

`tests/test_unicode_paths.py::LongPathTests` >260 karakterlik yolu kaynaktan
çalışan araçla test ediyor. PyInstaller EXE üzerinde aynı testi çalıştıracak
bir smoke adımı yok; `dist/` altındaki ikili dosyalar bu turdan eski.

**Yapılacak:** Paketleme turunda EXE için `--version` / uzun yol smoke testi.

## 7. Dosya symlink containment'ı uçtan uca doğrulanamadı

`iter_files` artık containment kontrolünü dizin/dosya ayrımından **önce**
yapıyor, yani kök dışına çıkan bir **dosya** symlink'i de taramaya giremiyor.
Ama bu makinede `SeCreateSymbolicLinkPrivilege` yok (Developer Mode kapalı),
`os.symlink` `WinError 1314` veriyor ve dosya symlink'i oluşturulamıyor.

Sonuç: mevcut test yalnız junction (dizin linki) senaryosunu koşuyor, o da
düzeltmeden önceki kodda da geçiyordu. Kod doğru görünüyor, kanıt yok.

**Yapılacak:** Developer Mode açık bir makinede, yükseltilmiş bir oturumda ya
da CI'da dosya symlink'i kuran bir regresyon testi koş.

## 8. Atfedilemeyen `<AD>.<UZANTI>.tmp` artığı — kapıyı aralıklı düşürüyor

Tam süit koşularının küçük bir kısmında temizlik sırasında bir test temp
dizininde tanınmayan bir `.tmp` girdisi beliriyor ve `DiagnosticTempDir`
`InconclusiveCleanupError` fırlatıyor. İki kez gözlendi:

- `hvt-test-*` içinde 0 baytlık `KNOWN_FILES.JSON.tmp` (dosya biçimi),
- `hvt-migration-*/user/HashTool` dizini `WinError 145` ile silinemedi
  (dizin biçimi — aynı aile, temizlik penceresinde beliren girdi).

Sıklık: ~30 tam süit koşusunda 2. Bu **kasıtlı**:
süreç düzeyinde kanıt olmadan dosyayı "başka bir programın" ilan etmek, gecikmeli
kendi yazıcımızın tanınmayan bir adın arkasına saklanmasına izin verirdi
(`tests/test_support_harness.py::test_unidentified_file_is_inconclusive_not_a_pass`).

Eldeki kanıt dışarıyı gösteriyor ama **atıf yapılmadı**:

- Ürünün atomik yazıcısı `hvt<5 hex>.tmp` üretiyor (`core/atomic_io.py`); büyük
  harfli `KNOWN_FILES.JSON.tmp` biçimini hiçbir kod yolu üretmiyor.
- Önceki turda 300 denemelik izole deney, ürün kodunun 0 leftover ürettiğini
  gösterdi.
- Ad biçimi (gerçek dosya adı + `.tmp`, büyük harf) bir filtre sürücüsünün
  (Defender / arama indeksleyici) silme penceresinde gölge kopya oluşturmasına
  uyuyor.

**Yapılacak:** Süreç düzeyinde araçla (Sysinternals Process Monitor, ETW
`FileIo` sağlayıcısı veya bir minifilter izi) dosyayı hangi sürecin yarattığını
tespit et. Atıf yapılırsa `_classify_leftovers`'a gerekçeli bir istisna
eklenebilir; yapılamazsa kapı olduğu gibi kalmalı — aralıklı kırmızı, sessiz
yeşilden iyidir.

## 9. Gelişmiş sekmelerinde iptal yok ve kapanışta thread terk ediliyor

Madde 3 Trust Check için kapandı; Gelişmiş > Hash / Verify / Report sekmeleri
hâlâ iptal edilemiyor. Üçü de tek bir çıkış noktasından geçiyor
(`HashToolApp.run_async`, `gui/app.py:488`), yani iptal oraya eklenirse üçü
birden kazanır.

Eksikler:

- `_Worker` (`gui/app.py:108-147`) bir daemon thread + kuyruk; **iptal jetonu
  yok**, session kimliği yok, join yok.
- Çekirdek API'ler iptali zaten destekliyor ama GUI geçmiyor:
  `build_manifest_for_folder(..., cancel=...)` (`core/manifest_manager.py`,
  her dosyadan önce yoklanıyor) ve `Verifier.verify(..., cancel=...)`
  (`core/verifier.py`). Sözleşme `() -> bool` yoklanan yüklem; bir
  `ScanSession` `cancel=lambda: session.cancelled` ile birebir uyuyor.
- **Asıl kusur:** `HashToolApp.destroy()` yalnız `_shutdown_active_scans()`
  (Trust Check) ve `_cancel_scheduled_callbacks()` çağırıyor; `self._worker`
  ne iptal ediliyor ne join'leniyor. Yani çalışan bir klasör hash'i sırasında
  pencere kapatılırsa thread daemon olarak **terk ediliyor** — Trust Check
  için düzeltilmiş olan sınıfın aynısı burada açık.
- Çalıştır düğmeleri anonim yerel değişken (`gui/app.py:616-618, 796-798`),
  `self`'e atanmıyor; hiçbir kod onları pasifleştiremiyor. Bir "meşgul"
  girişi yok — kopyalanacak desen `TrustCheckView._set_busy`.

**Yapılacak:** `run_async`'e iptal jetonu; durum çubuğuna (pack kullanan
`_build_statusbar`) İptal düğmesi; iki çekirdek çağrıya `cancel=` geçir;
`destroy()` içinde bounded join. Önce kırmızı test.
