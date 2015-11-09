# mta
Yazılım Tanımlı Sistem Yönetimi
USOM'daki zararlı alanları alıp zimbra ve postfix sunucuların reject dosyalarına zararlı etki alanını kaydeder.
Sunucu servisini yeniden başlatır.
SSH ile sisteme parolasız giriş için sertifikaların oluşturtulmasına ihtiyaç var.

Kullanım:
  mta-reject-guncelleyici.py <mta_sunucu> <opsiyonel: engellenecek domain adi>
