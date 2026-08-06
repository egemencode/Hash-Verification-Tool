# P1 Backlog

Bu turda (red-team P0 kapanışı) **kapsam dışı** bırakılan, bağımsız denetimde
tespit edilmiş maddeler. Hiçbiri güvenlik kararlarını yanlış üretmiyor; hepsi
kullanılabilirlik/tutarlılık sorunu.

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

## 3. Kullanıcıya görünür "İptal" düğmesi yok

İptal altyapısı çalışıyor (`ScanSession.cancel()`, pipeline aşama sınırlarında
kontrol ediyor, `shutdown()` bounded join yapıyor) ama tarama sırasında
kullanıcının basabileceği bir düğme yok — yalnız pencere kapatma/dil değişimi
iptali tetikliyor.

**Yapılacak:** Tarama sırasında etkin "İptal" düğmesi; iptal sonrası terminal
kart (`_show_terminal_failure` zaten hazır).

## 4. Ayarlar'daki "Anahtarı Test Et" için ortak görev yöneticisi yok

`SettingsView._on_test` kendi thread'ini açıyor; `ScanController`'dan bağımsız.
Bu thread iptal edilemiyor, uygulama kapanışında beklenmiyor ve `after()`
callback'i `_poll_after_id` disiplinine tabi değil.

**Yapılacak:** Uygulama geneli tek görev yöneticisi (session kimliği, iptal,
bounded join, tek scheduler) ve Ayarlar test akışının ona bağlanması.
