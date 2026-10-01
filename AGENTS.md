# Короткие названия файлов

В этом репозитории пользователь может ссылаться на файлы следующими названиями:

| Название в сообщении | Файл |
| --- | --- |
| geo, гео, Shadowrocket geo, SR geo | `Shadowrocket/gambino-sr-geo-ru.conf` |
| rules, правила, Shadowrocket rules, SR rules | `Shadowrocket/gambino-sr-rules.conf` |
| proxy, прокси, Clash proxy, Clash прокси | `Clash/gambino-proxy.yaml` |
| proxy mrs, прокси mrs, бинарный proxy | `Clash/gambino-proxy.mrs` |
| dns, ДНС, Clash dns, Clash ДНС | `Clash/gambino-dns.yaml` |

Сначала разрешай название по этой таблице и открывай соответствующий файл. Не проси пользователя повторять полный путь, ссылку или содержимое доступного файла.

Слова «этот файл» и «в нём» относятся к последнему явно обсуждавшемуся файлу, если контекст не указывает на другой. Если пользователь называет раздел, например «DNS в geo», работай с этим разделом указанного файла.

Если название неоднозначно, сначала используй контекст сообщения и текущей задачи. Уточняй только когда остаются несколько подходящих файлов и выбор влияет на результат.

`Clash/gambino-proxy.mrs` генерируется из `Clash/gambino-proxy.yaml` командой `mihomo convert-ruleset domain yaml`. Редактируй исходный YAML, а не бинарный MRS. Автообновление настроено в `.github/workflows/update-proxy-mrs.yml`.
