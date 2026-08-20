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

## 4. ~~Ayarlar'daki "Anahtarı Test Et" için ortak görev yöneticisi yok~~ — YARISI KAPANDI

### ✔ Koşucu yazıldı, Ayarlar ona bağlandı (`core/task_runner.py`)

`SettingsView._on_test` kendi thread'ini açıyor, thread iptal edilemiyor,
kapanışta beklenmiyor ve cevabı **worker thread'inden** `self.after(0, …)` ile
geri veriyordu.

Bunun bedeli düzensizlik değil, **yanlış cevap**: anahtarı yapıştır → Test →
yanlış olduğunu gör → doğrusunu yapıştır → Test. İki sorgu havada; sonra biten
ekranı yazıyor. Kullanıcı, çoktan düzelttiği anahtar için *"Anahtar reddedildi"*
okuyor. `ScanSession`'ın var olma sebebiyle aynı kusur — geç gelen cevabın
yanlış özneye iliştirilmesi — ve Ayarlar'da erişilebilirdi çünkü orada
"güncel" diye bir kavram yoktu.

Koşucu dört sorumluluğu tek yerde topluyor: kimlik, işbirlikçi iptal, sınırlı
join ve **kuyrukla teslimat**. Teslimat kuyrukla, çünkü Tkinter başka bir
thread'den gelen `after()`'ı ancak ana döngü koşuyorsa kabul ediyor; yok
edilmiş pencerede ise worker thread'inde patlıyor ve orada istisna basılıp
yutuluyor. Üstünlük **kimlikle** belirleniyor, varışla değil: iptal bloke bir
isteği kesemez, dolayısıyla "varışta reddedilir" elde edilebilecek tek garanti.

Testler: `tests/test_task_runner.py` (8), `tests/test_gui_key_test_task.py` (3).

### ✖ Kalan: Gelişmiş sekmeleri ve Trust Check hâlâ kendi mekanizmalarında

`gui/app.py`'deki `_Worker` ve `core/scan_controller.py` olduğu gibi duruyor.

**§6B'de taşınmadılar — ve bu bilinçli bir karar, ertelenmiş bir iş değil.**
`_Worker`'a "boşluğu var mı" diye soruldu, cevap hayır çıktı: aynı anda tek
worker çalışabildiği için (`run_async` ikinciyi "Meşgul" diyaloğuyla
reddediyor) **kimliğe ihtiyacı yok**; iptal jetonu, sınırlı join ve takipli
`after` disiplini zaten var. Manifest **yazan** yolu, davranış kazancı olmadan
yeniden yazmak kötü bir takas. Koşucu, o kod bir dahaki sefere değişmesi
gerektiğinde hedef biçim olarak duruyor.

### ✔ §6B'de bunun yerine gerçek bir kusur çıktı: teslim penceresi

`_poll` önce kuyruğu boşaltıp **sonra** thread canlı mı diye soruyordu. Worker
terminal mesajını kuyruğa koyup *ondan sonra* dönüyor; iki satırın arasında
biterse boşaltma boş dönmüş, thread ölü görünüyor ve koşu "bildirecek bir şey
yok" sayılıyordu. `_finish` aynı zamanda worker referansını da düşürdüğü için
mesaj **kalıcı olarak** kayboluyordu.

- Hash koşusu: manifest diske yazılıyor, ekran hiçbir şey söylemiyor.
- Doğrulama: karşılaştırma sonucu hiç görünmüyor.
- **En kötüsü:** hata düşerse durum çubuğu `status.ready` yazıyor — olmamış
  bir başarı bildiriliyor.

Düzeltme: thread ölü göründüğünde bir kez daha boşalt.
Testler: `tests/test_gui_worker_race.py` (3).

> **Trust Check'te bu kusur neden yok:** oradaki poll, yeniden zamanlamaya
> *denetleyicinin* `is_busy`'sine bakarak karar veriyor — thread'in canlılığına
> değil. Sonuç teslim edilene kadar denetleyici meşgul kalıyor, dolayısıyla
> pencere kapanmıyor. `_Worker`'ın böyle bir durumu yoktu. Birleştirme
> yapılacaksa taşınması gereken şey budur: **thread değil, durum otoritesi.**

> Küçük bir kalıntı, bilerek: Ayarlar görünümü yalnız *güncel görev koşarken*
> yokluyor. Bayat bir cevap poll durduktan sonra gelirse kuyrukta okunmadan
> kalıyor. Zararsız (görünümle birlikte atılıyor) ve bir sonraki
> `drain_current` onu zaten kimliğinden eliyor — ama kapanmış saymayın.

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
  silme penceresinde gölge kopya oluşturmasına uyuyor.

### 2026-08-19 turunda eklenen kanıt (üçüncü gözlem + izole deneyler)

Üçüncü gözlem: `M.JSON.tmp`, `hvt-test-ixnawydc` içinde, 6 turluk kapı
koşusunun 4. turunda. `stat` `WinError 2` verdi — dosya listelendikten sonra
`stat` edilmeden önce **kayboldu**. Aynı aile: gerçek dosya adı (`m.json`),
büyük harf, `.tmp` eki.

**Tarayıcı kimliği düzeltildi.** Bu notta önceki tahmin "Defender / arama
indeksleyici" idi; **yanlış**. Ölçüldü:

- `Get-MpComputerStatus` → `RealTimeProtectionEnabled: False`. Defender'ın
  gerçek zamanlı koruması **kapalı**.
- Çalışan koruma süreçleri: `avp` (×2), `avpui` — **Kaspersky**; ayrıca
  `ksde`, `ksdeui` (Kaspersky EDR ajanı).
- `fltmc filters` → `0x80070005 Erişim engellendi`. Minifilter listesi
  **yükseltilmiş oturum olmadan alınamıyor.**

**İzole deneyler — hiçbiri hayaleti üretmedi (toplam 7600 tur):**

| Örüntü | Tur | Hayalet |
|---|---|---|
| Doğrudan yaz → sil | 3000 | 0 |
| Atomik yaz (`hvtXXXXX.tmp` → `os.replace`) → tam oku → sil | 4000 | 0 |
| Aynısı ama dosyayı **alt süreç** yazıyor | 600 | 0 |

Üçü de yalnız standart kütüphane kullandı; yani ürün kodu olmadan da
üretilebilir mi sorusunun cevabı **bu örüntülerde hayır**. Tetikleyici tek
başına yazma biçimi ya da süreç oluşturma değil. Gerçek süitte kalan farklar:
ağaç yapısı, `.exe`/imza örnekleri gibi tarayıcının ilgisini çeken içerik,
`tests/support.py::_rmdir_all`'un ağacı gezerek silmesi ve 75 saniyelik yoğun
G/Ç baskısı.

**Sıklık güncellemesi:** bu turda 6 turda 1. Önceki tahmin (~25'te 1) fazla
iyimser olabilir; tek ölçüm, kesin konuşmuyorum.

**Yapılacak:** **Yükseltilmiş** bir oturumda süreç düzeyinde iz al —
Sysinternals Process Monitor (`Operation: CreateFile`, `Path contains .tmp`)
ya da ETW `FileIo`. `fltmc filters` çıktısıyla Kaspersky minifilter'ının
(`klif`/`klam` ailesi) yüklü olduğunu da doğrula. Bu oturumda **yetki yoktu**,
o yüzden atıf yapılamadı. Atıf yapılırsa `_classify_leftovers`'a gerekçeli bir
istisna eklenebilir; yapılamazsa kapı olduğu gibi kalmalı — aralıklı kırmızı,
sessiz yeşilden iyidir.

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

## 10. ~~Koyu tema desteği yok~~ — KAPANDI

`gui/theme.py` renkleri beyaz zemine göre ayarlandı ve neredeyse tamamı koyu
zeminde AA'nın altına düşüyor (ölçüm, `#1e1e1e` zemine karşı):

| Token | Beyaz | Koyu |
|---|---|---|
| `OK` #2e7d32 | 5.13 | **3.25** |
| `DANGER` #c62828 | 5.62 | **2.97** |
| `INFO` #1565c0 | 5.75 | **2.90** |
| `TRACE` #6a1b9a | 9.39 | **1.78** |
| `MUTED` #616161 | 6.19 | **2.69** |

Yani koyu tema "bir bayrak çevirmek" değil: **ikinci bir palet** ve Tkinter'da
her widget için elle uygulama gerektiriyor (ttk'nın `vista`/`clam` temaları
Windows'un koyu modunu izlemiyor).

### ✔ Uygulandı (§8)

`gui/theme.py` artık iki palet tutuyor ve `apply()` açılışta Windows'a hangi
temayı giydiğini soruyor (`AppsUseLightTheme`, `HKCU\…\Themes\Personalize`).
Okunamazsa açık palete düşüyor: yanlış tahmin bütün pencereyi boyar.

**Koyu palet, açık paletin tersi değil — ikinci bir karar kümesi.** Renkler
tahmin edilmedi, ölçüldü; her biri kendi temasının **en zor zeminine** karşı
5.0:1 üstünde:

| Token | Açık | Koyu |
|---|---|---|
| `TEXT` | #444444 (8.55) | #f0f0f0 (12.42) |
| `MUTED` | #616161 (5.43) | #b8b8b8 (7.14) |
| `OK` | #2b742f (5.06) | #8ed48e (8.06) |
| `ATTENTION` | #a74b00 (5.05) | #f5bb70 (8.24) |
| `DANGER` | #c62828 (4.93) | #f79b94 (6.79) |
| `INFO` | #1565c0 (5.04) | #9ac8f0 (8.02) |
| `TRACE` | #6a1b9a (8.24) | #d4b3e8 (7.69) |

**Zor zemin temayla yer değiştiriyor.** Açıkta metin koyu, zorlandığı yer daha
*koyu* yüzey; koyuda metin açık, zorlandığı yer daha *açık* yüzey. İlk turda
"zor zemin hep koyu olandır" varsayımı iki rengi AA altında göndermişti; artık
`theme.hard_ground()` bunu hesaplıyor ve test iki yönü de ölçüyor.

**Vurgu rengi keskin kenardı.** Açık vurgu beyaz metni 5.38:1'de taşıyor; koyu
vurgu beyazı **2.01:1**'de taşıyor — okunmaz — siyahı 10.47:1'de. Bu yüzden
vurgunun eşlik ettiği yazı rengi palete ait, `apply()` içinde sabit değil.
`"#ffffff"` yazan bir test açık temayı geçer, diğerinde okunamaz bir birincil
düğme gönderirdi.

**ttk'nın ulaşamadığı widget'lar elle boyanıyor.** Günlük alanları düz
`ScrolledText` — bir Frame içinde Text ve Scrollbar — ve tema ne derse desin
Windows varsayılanlarını koruyorlar. Açık temada bu görünmezdi çünkü
varsayılanlar zaten uyuyordu.

Testler: `tests/test_gui_theme_contrast.py` iki paleti de yürüyor (16 test).

> **Menü çubuğu açık kalıyor.** Windows'ta menü çubuğunu işletim sistemi
> çiziyor ve Tk'ye söyleneni yok sayıyor; açılır menüler koyu oluyor, üstteki
> şerit olmuyor. Tk yerel koyu menü desteği kazanana kadar böyle. Gizlemek
> yerine adını koyuyorum.

### Bu turda elle bulunan kusur

`bullets_text` zeminini temadan, yazı rengini **Tk varsayılanından** alıyordu.
Açık temada bu görünmez bir şanstı; koyuda kömür üstüne siyah — hem de risk
hükmünün *gerekçesini* tutan kutuda. Palet kusursuz, zeminlerin hepsi biliniyor
olmasına rağmen kimse bir widget'ın **iki ucunu birbiriyle** karşılaştırmıyordu.

Artık karşılaştırıyor: `RenderedLegibilityTests` iki temada da her widget'ı
gezip yazısının kendi zemininde okunabildiğini şart koşuyor.

## 11. ~~Sonuç metni çekirdekten geliyor ve hâlâ tek dilli~~ — KAPANDI

Üç varsayılan ekranın **kendi yazdığı** her dize `t()` üzerinden geçiyor
(bkz. `tests/test_gui_language_coverage.py`). Ama ekranın asıl cümlesini —
risk özetinin başlığını, maddelerini ve öğüdünü — ekran yazmıyor:
`core/risk_engine.py` ve `core/smart_summary.py` üretiyor. Aynısı temel sürüm
sorularında (`core/baseline.py`), yerel kayıt ve imza mesajlarında
(`core/local_verify.py`, `core/signature_checker.py`) ve Doğrula sekmesinin
güven rozetlerinde (`gui/trust_presenter.py`) geçerli.

Yani İngilizce seçen bir kullanıcı artık bütün arayüzü İngilizce görüyor ama
tarama bitince **verdiği kararı Türkçe okuyor**.

### ⚠️ Düzeltme (2026-08-19): bu maddenin ilk gerekçesi yanlıştı

İlk yazılışında *"bu cümleler **CLI ile ortak**, o yüzden çevirmek dil durumunu
çekirdeğe taşımak demek"* deniyordu. **Ölçüldü, doğru değil:**

```
main.py -> trust_pipeline | trust_report | smart_summary | risk_engine  : hicbiri
```

`main.py` bu dört modülün hiçbirini import etmiyor. `build_summary` yalnız
`core/trust_pipeline.py` (GUI'nin tarama hattı) ve `core/trust_report.py`
(GUI'nin rapor dışa aktarımı) tarafından çağrılıyor. Yani **güven kontrolü
hattının tamamı grafik arayüze ait**; komut satırı `hash_utils`,
`manifest_manager`, `verifier`, `reporter`, `scan_policy` ve `key_files`
üzerinden gidiyor. Ortaklık iddiası uydurmaydı ve bu maddeyi olduğundan pahalı
gösteriyordu.

Ölçülen gerçek büyüklük:

| Yer | Türkçe dize satırı |
|---|---|
| `core/smart_summary.py` | 38 |
| `core/risk_engine.py` | 39 |
| `core/baseline.py` | 11 |
| `core/local_verify.py` | 16 |
| `gui/trust_presenter.py` | 26 |

Türkçe proza dayanan test satırı: `test_gui_wiring.py` 13, diğerlerinde 1–2.

### Seçilen yol (uygulanmadı, gerekçe yazıldı)

**Çekirdek metin değil, anahtar döndürsün; sunum katmanı çevirsin.** Sebep,
kod tabanının kendi damarı: `gui/trust_presenter.py` zaten *"karar kuralları
ile ifadeyi ayır"* diye var ve docstring'i bunu söylüyor. `core/risk_engine.py`
de bir puan değil bir karar tablosu. Çekirdeğin `t()` çağırması, sunumu
çekirdeğe geri sokardı.

Bedeli dürüstçe: `SmartSummary.bullets` düz metin listesi olmaktan çıkıp
(anahtar, parametre) taşır; `as_text()` bir render'a ihtiyaç duyar;
`core/trust_report.py`'nin ürettiği HTML/JSON rapor da render edilmiş metni
almak zorundadır.

### ✔ Uygulandı (§7)

`core/phrases.py` eklendi: bir `Phrase`, cümlenin **kimliği** artı içine giren
değerler. Hangi cümlenin doğru olduğuna çekirdek karar veriyor, kelimeleri
`gui/trust_presenter.py` seçiyor.

Kapsanan yüzey:

- `core/risk_engine.py` — risk başlığı **ve bütün kanıt satırları** (faktör
  adı + açıklaması). Artık içinde tek bir Türkçe dize yok.
- `core/smart_summary.py` — özet maddeleri ve öğüt satırı. `as_text()`
  **kaldırıldı**: bir özeti düz metne indirgemek dil seçmeyi gerektirir ve bu
  modül tam da onu yapmamalı. Karşılığı `RenderedSummary.as_text()`.
- `gui/trust_presenter.py` — manifest güven rozetleri ve doğrulama başlıkları
  (modül düzeyinde sabit tablo olduğu için aynı "import anında donma" kusuru
  vardı, anahtara çevrildi) + başlangıç uyarısı.
- `core/trust_report.py` — JSON ve HTML raporun tamamı, belgenin `lang`
  niteliği dâhil. `to_dict`, `export_json` ve `export_html` artık bir
  `translate` çağrılabiliri **zorunlu** alıyor; varsayılan bırakmak, sessizce
  `risk.headline.high` ile dolu geçerli bir belge üretirdi ve kimse fark etmezdi.

Raporda her bulgu **iki yazımla** duruyor: insanın okuduğu kelimeler ve
programın eşleştirebileceği anahtar (`detail_key`, `headline_key`). Çevrilmiş
bir cümle kararlı bir tanımlayıcı değildir.

Testler: `tests/test_verdict_language.py` (6). Ayrıca prozeye bakan **sekiz
mevcut test anahtara bakacak şekilde güçlendirildi** — anahtar "hangi kararı
verdi"yi söyler, alt dize eşleşmesi yalnızca "metinde şu kelime geçti"yi.
`test_vt_freshness` bunun en belirgin örneğiydi: üç Türkçe kelimeden herhangi
biri *herhangi bir* maddede geçse geçiyordu.

### ✔ §7B — uygulamanın söylemeyi seçtiği her şey

**Önce bir ölçüm düzeltmesi.** §7B "üç modül, ~22 dize" diye tahmin edilmişti.
Ölçülünce `core/` ve `utils/` altında **136** Türkçe dize çıktı (docstring
hariç), 15 modülde. Tahmin, `core/scan_policy.py`'nin `gui/app.py` tarafından
gösterilen uyarılarını da atlamıştı.

**Çizilen sınır — ve bu bir karar, mazeret değil:**

> Uygulamanın **seçtiği** metin çevrilir. İşletim sisteminin, dosya sisteminin
> ya da uzak bir API'nin **bildirdiğini aktaran** metin çevrilmez.

Aktarılan tanı metni yeniden yazılırsa onu yararlı kılan ayrıntıyı kaybeder
(`PermissionError`'ı adlandıran bir satırı "dosya okunamadı"ya indirgemek gibi),
üstelik bir kısmı `key_files.py` / `manifest_signing.py` gibi imzalama
yollarında ve salt ifade için oraya dokunmak kötü bir takas.

Çevrilenler:

| Modül | Ne |
|---|---|
| `core/scan_policy.py` | Hash isteğini reddeden/niteleyen 5 politika uyarısı |
| `core/baseline.py` | Temel sürüm soruları (`decision_prompt()`) |
| `core/local_verify.py` | Kaydın dosya hakkında söyledikleri (sonuç mesajları) |
| `core/trust_pipeline.py` | 8 ilerleme adımı + "dosya tarama sırasında değişti" |

**Tablo `gui/i18n.py`'den `core/i18n.py`'ye taşındı.** Sebebi mimarî:
`scan_policy` iki ön yüzün de uyduğu kuralları tutuyor ve bir çekirdek
modülünün `t()` için `gui`'yi import etmesi, o dosyanın var olma sebebini
tersine çevirirdi. `gui/i18n.py` yeniden dışa aktarım olarak duruyor, hiçbir
görünüm importu değişmedi. **CLI'ın çıktısı bit bit aynı:** komut satırı hiç
`set_language` çağırmıyor, varsayılan Türkçede kalıyor.

**Bu katman kendini render ediyor** — hüküm gibi çevrilmemiş `Phrase`
döndürmüyor. Sebebi: üretildikleri anda tüketiliyorlar ve `main.py` bunları
stderr'e basıyor, elinde render edecek bir sunum katmanı yok.
`PolicyNotice.message` düz `str` olarak kaldığı için CLI ve Hash sekmesinde
**tek satır değişmedi**. Anahtar, uyarının kendi `code`'undan türüyor; ikisi
birbirinden ayrı yeniden adlandırılamıyor.

Testler: `tests/test_notice_language.py` (7).

> **Neden kaynakta Türkçe harf arayan bir sınır testi yok:** bu dalın kuralı
> "davranış testi yaz, kaynak içinde kelime arayan test yazma".
> Sınırı `test_every_policy_code_has_a_sentence` tutuyor — politika beş
> yapılandırmanın hepsinden geçiriliyor ve her uyarının anahtarı değil
> **cümlesi** dönmek zorunda. Çevirisiz eklenen bir uyarı sessizce
> `policy.something_new` göstermek yerine testi düşürüyor.

### ✖ Bilerek çevrilmeyen (aktarılan tanı metni)

`core/key_files.py` (25), `core/manifest_manager.py` (14), `utils/settings.py`
(13), `core/history_manager.py` (9), `core/manifest_signing.py` (9),
`core/signature_checker.py` (9), `core/vt_client.py` (9), `core/secret_store.py`
(4), `core/file_info.py` (3), `core/verifier.py` (2), `core/atomic_io.py` (1)
ve `core/local_verify.py`'nin depo hataları.

Bunlar `str(exc)` olarak ekrana gelebiliyor. Çevrilmeleri isteniyorsa her özel
istisnanın bir `Phrase` taşıması ve GUI'nin onu render etmesi gerekir — ayrı
bir tur, ve imzalama yollarına dokunduğu için ayrı bir risk.
