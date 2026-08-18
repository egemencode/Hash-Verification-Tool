# P1 Backlog

Bu turda (red-team P0 kapanışı ve ardından §3 CLI/klasör sözleşmesi) **kapsam
dışı** bırakılan, bağımsız denetimde tespit edilmiş maddeler. Hiçbiri güvenlik
kararlarını yanlış üretmiyor; hepsi kullanılabilirlik/tutarlılık sorunu.

> §3 turunda madde 3'ün çekirdek yarısı kapandı: `build_manifest_for_folder`
> ve `Verifier.verify` artık `cancel` yordamı alıyor, iptal edilen tarama ayrı
> bir `ScanState.CANCELLED` terminal olayı üretiyor ve hiçbir koşulda manifest
> olarak kaydedilmiyor. Eksik olan hâlâ **kullanıcıya görünür düğme**.

## 1. ~~Ayarlar'da "API Anahtarını Kaldır" eylemi yok~~ — KAPANDI

Ayarlar > VirusTotal bölümüne "Anahtarı Kaldır" düğmesi eklendi: onay sorusu
(varsayılan *hayır*), `clear_api_key()` + `save()`, başarısız yazmada draft'ı
canlı ayarlardan yeniden kurup hatayı bildirme, ekranda sonuç.

Neden gerekliydi: alanı boşaltıp kaydetmek **eşdeğer değil**. Sıradan bir
kaydetme, çözülemeyen bir token'ı bilinçli olarak koruyor (çünkü
"çözülemeyen"i "yok" saymak bir kullanıcının tek kopyasını yok etmişti). Bu
doğru varsayılan, ama DPAPI bağlamı değişen kullanıcıyı (başka Windows hesabı,
geri yüklenmiş profil) ne kullanabildiği ne kurtulabildiği bir anahtarla baş
başa bırakıyordu — üstelik `utils/settings.py`'nin kendi uyarısı ona
*"'Anahtarı Kaldır' diyebilirsiniz"* diyordu, **var olmayan bir düğmeyi**
tarif ederek.

Testler: `tests/test_gui_settings_state.py::UnreadableKeyRemovalTests`.

> Düğme her zaman etkin; kayıtlı anahtar yokken basmak zararsız bir işlem.
> "Silinecek bir şey yoksa pasifleştir" kuralı, `secret_state`'i takip eden
> ikinci bir durum daha yaratacağı için bilinçli olarak eklenmedi.

## 2. ~~Menü dili ile Ayarlar dili iki ayrı state kullanıyor~~ — KAPANDI

Dil üç yerde tutuluyordu: i18n modülü, `HashToolApp._settings` (ham dict) ve
`AppSettings.language`. `_switch_language` ilk ikisini güncelliyor, üçüncüsünü
bırakıyordu. Ayarlar sekmesi dil değişiminde yeniden kurulduğu ve draft'ını
`AppSettings`'ten aldığı için **bayat** dili gösteriyordu; sonraki her Kaydet
(ör. yalnızca geçmiş limitini değiştirmek için basılan) o bayat değeri diske
yazıp arayüzü ona döndürüyordu — kullanıcının yaptığı ve etkisini gördüğü
seçimi sessizce geri alarak.

`_switch_language` artık `self._app_settings.language`'ı da güncelliyor.

Testler: `tests/test_gui_settings_state.py::LanguageStateTests`.

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

## 5. ~~GUI'de imzalama akışı yok~~ — KAPANDI

### ✔ Doğrula sekmesi — güvenilen anahtar

Doğrula sekmesine "Güvenilen anahtar (opsiyonel)" alanı eklendi. CLI ile aynı
sözleşme: `load_public_key` `.pub` dosyası, özel anahtar dosyası (genel yarıyı
**türetir**) ve ham hex kabul ediyor. Anahtar hem `Manifest.load`'a hem
`Verifier`'a geçiyor.

Neden gerekliydi: `SignatureState.TRUSTED` — bir eşleşmenin gerçekten "bu
dosyalar o anahtarı tutan kişinin yayımladıklarıdır" dediği tek durum —
güvenilen anahtar gerektiriyor. GUI hiçbirine geçmiyordu, dolayısıyla rozet
kullanıcının diskinde ne olursa olsun *"imzalı ama kaynağı doğrulanmadı"*dan
iyisini gösteremiyordu. Ekran bunu kabul edip kullanıcıyı **CLI'a
yönlendiriyordu** — `core/scan_policy.py`'nin bir önceki turda ortadan
kaldırdığı asimetrinin aynısı: uzman arayüz kaynağı doğrulayabiliyor,
varsayılan arayüz doğrulayamıyor.

Ek davranışlar (hepsi testle tutuluyor):

- Anahtar **yükleme anında** kontrol ediliyor, tarama sonrasında değil. Büyük
  bir ağacı gösteren kullanıcı, zaten güvenmediğimiz bir referans uğruna tam
  bir hash koşusunu beklemiyor.
- Çözülemeyen/geçersiz anahtar dosyası girdi hatası olarak bildiriliyor —
  sessizce güvensiz karşılaştırmaya düşülmüyor (o ekran başarılı olandan
  ayırt edilemezdi).
- Yanlış anahtar CLI'daki `EXIT_UNTRUSTED_REFERENCE` ile aynı yolu izliyor:
  karşılaştırma durduruluyor, kurcalama uyarısı gösteriliyor.

Testler: `tests/test_gui_trusted_key.py` (5 davranış testi).

### ✔ Hash sekmesi — imzalama

"İmzalama anahtarı (opsiyonel)" alanı eklendi. GUI'den üretilen manifest artık
imzalanabiliyor ve **gerçek CLI `verify --trusted-key` ile doğrulanıyor** —
testin iddiası bu, "imza bloğu var" değil.

CLI ile aynı davranışlar:

- `sign_key` artık `evaluate_hash_request`'e geçiyor, yani anahtarın taranan
  klasörün içinde ya da manifestin yanında olması **aynı ortak karar
  tablosuyla** engelleniyor. Tablo zaten vardı; grafik yol ona danışmıyordu.
- Anahtar **tarama başlamadan** çözülüyor. Okunamayan anahtar girdi hatası;
  sonradan fark etmek ya işi çöpe atmak ya da — çok daha kötüsü — kullanıcı
  imzaladığını sanırken manifesti imzasız yazmak olurdu.
- İmza kaydetmeden **önce** ve yalnız `build.complete` iken atılıyor: bilerek
  eksik bir tarifi imzalamak, tam da bahsetmediği boşluklara tanıklık etmek
  olurdu.
- Tek dosya modunda anahtar reddediliyor (imza envantere tanıklık eder).
- Sonuç günlüğü eşleşen `.pub` yolunu yazıyor — karşı tarafın doğrulayamadığı
  imza süstür.

Testler: `tests/test_gui_signing.py` (6 davranış testi).

> Not: `main.py`'nin `load_private_key` sarmalayıcısı `.private_hex` çıkarıyor;
> `core.key_files.load_private_key` ise `PrivateKeyFile` nesnesi döndürüyor.
> GUI doğrudan çekirdeği kullandığı için hex'i kendisi çıkarıyor.

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

## 9. ~~Gelişmiş sekmelerinde iptal yok ve kapanışta thread terk ediliyor~~ — KAPANDI

`_Worker` artık kendi iptal jetonunu taşıyor ve hedefe `(emit, cancel)` geçiyor;
durum çubuğuna İptal düğmesi eklendi (tek worker yuvası Hash / Verify / Report
üçünü de beslediği için tek düğme hangisi çalışıyorsa onu durduruyor);
`build_manifest_for_folder` ve `Verifier.verify` çağrılarına `cancel=` geçiliyor;
iptal edilen koşu ayrı bir `"cancelled"` terminal mesajı üretiyor (yoksa
`_on_done` eksik build'i "başarısız tarama" diye raporluyordu).

**Asıl kusur da kapandı:** `destroy()` artık `_shutdown_background_worker()`
çağırıyor — iptal + 5 sn bounded join. Öncesinde pencere kapatılınca worker
terk ediliyordu ve o worker `build.save()`'i kendisi çağırdığı için **kullanıcı
vazgeçtiği hâlde manifest diske yazılıyordu**; bir hash doğrulama aracında
terk edilmiş bir taramanın referans dosyasına dönüşmesi demekti.

Testler: `tests/test_gui_advanced_cancel.py` (4 davranış testi), dördü de
`tools/verify_fix_coverage.py` ile tutuluyor.

> **Kalan:** Çalıştır düğmeleri hâlâ anonim yerel değişken
> (`gui/app.py`, HashTab/VerifyTab `_build`), `self`'e atanmadığı için tarama
> sırasında pasifleştirilemiyor. `run_async` tekrar basmayı zaten "Meşgul"
> diyaloğuyla reddediyor, yani veri güvenliği sorunu değil; sekmelerin
> `TrustCheckView._set_busy` gibi bir meşgul girişine kavuşması bir
> kullanılabilirlik işi olarak duruyor.
