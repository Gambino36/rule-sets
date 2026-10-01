# rule-sets

`Clash/gambino-proxy.yaml` — исходный доменный набор правил для mihomo.
`Clash/gambino-proxy.mrs` — его бинарная версия. Записи `+.example.com`
сохраняют охват самого домена и его поддоменов.

После изменения YAML в ветке `master` GitHub Actions автоматически пересобирает
MRS и коммитит его, если результат изменился. В pull request конвертация только
проверяется. Также доступен ручной запуск workflow **Update proxy MRS** на `master`.
Некорректные доменные записи останавливают обновление, чтобы правила не терялись
при конвертации. Исходный YAML остаётся файлом для редактирования.

Подключение MRS в конфигурации mihomo:

```yaml
rule-providers:
  gambino-proxy:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/Gambino36/rule-sets/master/Clash/gambino-proxy.mrs
    path: ./rule-sets/gambino-proxy.mrs
    interval: 86400

rules:
  - RULE-SET,gambino-proxy,PROXY
```

`PROXY` нужно заменить на имя вашей группы прокси. `interval: 86400` задаёт
обновление набора на устройстве раз в сутки; обновление файла на GitHub происходит
после каждого изменения исходного YAML.

Ручная сборка той же версией mihomo, что используется в workflow (`v1.19.32`):

```sh
mihomo convert-ruleset domain yaml Clash/gambino-proxy.yaml Clash/gambino-proxy.mrs
```
