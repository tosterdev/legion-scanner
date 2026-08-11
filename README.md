# legion-scanner

Go-пакет `portscan` для connect-сканирования TCP-портов.

## Использование

```go
scanner, err := portscan.New(
    portscan.WithConcurrency(100),
    portscan.WithConnectTimeout(500*time.Millisecond),
)
if err != nil {
    return err
}

results, err := scanner.Scan(
    ctx,
    []string{"192.168.1.10", "192.168.1.11"},
    portscan.Range(1, 1000),
)
if err != nil {
    return err
}

for result := range results {
    fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State.String())
}
```

## Публичный API

### `portscan.New(opts ...Option) (*Scanner, error)`

Создаёт экземпляр сканера.

Опции:
- `portscan.WithConcurrency(n int)` — ограничение на число одновременных подключений.
- `portscan.WithConnectTimeout(d time.Duration)` — таймаут connect-операции.

### `(*Scanner).Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error)`

Запускает сканирование и возвращает канал `results`, который закрывается после завершения всех уже запущенных проверок.

Во время сканирования используются:
- `concurrency` воркеров (параллельные dial'ы);
- канал задач `host+port`;
- канал результатов `results`.

### Наборы портов
- `portscan.Range(from, to int)` — включительный диапазон (при `from > to` диапазон разворачивается).
- `portscan.Ports(p1, p2, ...)` — список портов.
- `portscan.Join(set1, set2, ...)` — объединение нескольких наборов.

Поведение на невалидных портах: возвращается ошибка на этапе подготовки `Scan`.

### `Result` и `State`

`Result` содержит `Host`, `IP`, `Port`, `State`, `Duration`, `Err`.

`State` различает: `Open`, `Closed`, `Timeout`, `Unreachable`, `Canceled`, `Error`.

Пример: `result.State.String()` возвращает человекочитаемое имя состояния.

## Тесты

Запуск:

```bash
go test ./...
go test -race ./...
```

### Цели (`internal_test.go`)

- `TestResolveTargets_emptyHost` — пустой хост / пробелы.
- `TestResolveTargets_invalidAddress` — некорректный адрес.
- `TestResolveTargets_unresolvableDNS` — неразрешимое DNS-имя.
- `TestResolveTargets_duplicates` — повторяющиеся цели (IP и DNS без учёта регистра).
- `TestResolveTargets_multipleIPsFromDNS` — одно DNS-имя → несколько IP.
- `TestResolveTargets_ipv4AndIPv6` — IPv4 и IPv6.
- `TestResolveTargets_ipv4LiteralUsesCanonicalIP` — канонический IP в результате.

### Порты и классификация (`scanner_test.go`)

- `TestPortSetRangeSwap` — `Range(from, to)` при `from > to`.
- `TestClassifyDialErrorCanceled` / `Timeout` / `Closed` — разбор ошибок dial.
- `TestScan_emptyHosts` — пустой список hosts.
- `TestScanOpenClosed` — открытый и закрытый порт на `127.0.0.1`.

### Конкурентность (`scanner_concurrency_test.go`)

- `TestScan_contextCancelClosesResults` — отмена через `context`, остановка новых заданий, закрытие `results`.
- `TestScan_reuseScanner` — повторное использование одного экземпляра сканера.
- `TestScan_slowResultReader` — медленное чтение результатов (backpressure).
- `TestScan_concurrencyLimit` — лимит параллельных подключений (`WithConcurrency`).