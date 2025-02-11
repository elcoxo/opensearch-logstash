# Введение

Данная работа состоит из:
- описания основных моментов установки ELK-стека(в данном случае OpenSearch, Logstash, OpenSearch Dashboards) на локальной машине;
- настройке и применению в мониторинге состояния системы на основе журналов лога, автоматизации сбора данных;
- построения дашбордов для отображения актуального состояния инфраструктуры;

# 1. Теоретическая часть

Современные системы информационной безопасности требуют постоянного мониторинга, сбора логов и анализа событий для выявления угроз. ELK-стек позволяет создать систему для автоматизированного обнаружения аномалий, поиск по инцидентам и их решению.

ELK-стек это набор компонентов обеспечивающий возможность безопасно и надежно собирать данные с разных систем и приложений, осуществлять поиск по разным источникам, анализировать журналы лога, а так же визуализировать их в реальном времени.

![alt](/img/elk.png)

## 1.1 OpenSearch

OpenSearch - это распределенная RESTful система с поисковым и аналитическим движком для работы с большими объёмами данных, обеспечивая быстрое хранение, индексацию и поиск. Она использует кластерную архитектуру, позволяющая в реальном времени добавлять новые узлы в кластер, где данные автоматически распределяются и реплициюруются, что дает системе отказоустойчивость и легкую адаптацию к увеличению нагрузки.

Данные хранятся в виде индексов, состоящие из множества JSON-документов. Внутри индекса данные разделяются на шарды, которые распределяются между узлами кластера. Структура хранения данных обеспечивает быстрый поиск по документам, фильтрацию и кеширование для часто запрашиваемых результатов.

OpenSearch содержит различные плагины, расширяющие возможности движка в том числе для безопасности и защиты данных. Пакет OpenSearch-Security содержит контроль доступа к данным и API по ролям(RBAC), поддержку TLS/SSL-шифрования для защиты трафика от перехвата и модификации данных, а так же использование сертификатов безопасности. Среди других полезных плагинов можно выделить поддержку детального лога для аудита и различные механизмы аутентификации: SAML, SSO, API-токены и внешние источники авторизации.

На данный момент OpenSearch распространяется под лицензией Apache 2.0 при участии сообщества и крупных компаний.


## 1.2 OpenSearch Dashboards

OpenSearch Dashboards - это сервис для визуализации данных, хранящимися в OpenSearch. Создание интерактивных графиков, отчетов и панелей, а также применение фильтров делает анализ данных более наглядным. Информативные панели можно легко изменять, импортировать и экспортировать между другими инсталляциями с OpenSearch. OpenSearch Dashboards поддерживает язык запросов Dashboards Query Language (DQL), который позволяет фильтровать и искать данные внутри визуализаций.

## 1.3 Logstash

Logstash - это инструмент, предназначенный для приема данных из различных источников(файлы, базы данных, TCP/UDP-соединений), преобразовывать их и отправлять в нужное место назначение, например, OpenSearch. Logstash имеет встроенный фильтр Grok для разбора из неструктурированных данных в структурированные JSON-документы. Grok сопоставляет текстовые данные с регулярными выражениями и имеет 100 встроенных шаблонов с готовыми обозначениями.

## 1.4 Elastic Beats

Elastic Beats - набор легковесных агентов предназначенный для сбора журналов или метрик с разных источников в инфраструктуре и пересылке их на Logstash. Использование агентов актуально при множество серверов, устройств или приложений, которые генерируют данные. В противном случае Logstash может справиться с задачей сбора и обработки данных самостоятельно. 

Filebeat - это один из самых популярных Beats-агентов, предназначенный для сбора и отправки логов из файлов. Он отслеживает изменения в файлах логов, собирает новые записи и отправляет их напрямую в Logstash или через брокер сообщений Kafka. Такая сборка помогает распределять нагрузку при высоком трафике. 

В данной работе использование агентов избыточна поэтому за агрегацию и обработку будет отвечать Logstash

# 2. Установка и настройка

> [!NOTE]
> Некоторые этапы установки и настройки инфраструктуры были опущены в этом документе с целью сохранения его оптимального объема.

## 2.1 OpenSearch

### 2.1.1 OpenSearch

Скачаем OpenSearch с официального сайта (https://opensearch.org/downloads.html) и разархивируем его в `/opt/opensearch/`

При настройке OpenSearch и Logstash рекомендуется создавать отдельных пользователей для разграничения прав.

Пользователь `opensearch`

```bash
useradd opensearch -g opensearch -M -s /bin/bash
passwd opensearch
```

Пользователь `logstash`

```bash
useradd logstash -g logstash -M -s /bin/bash
passwd logstash
```

Даем право владельца `opensearch` для каталогоа `/opt/opensearch`

```bash
chown -R opensearch:opensearch /opt/opensearch
```

Создадим каталог для логов и дадим право владельца `opensearch`

```bash
sudo mkdir /var/log/opensearch
sudo chown -R opensearch /var/log/opensearch
```

Перед установкой, начиная с OpenSearch 2.12, необходимо определить пароль администратора, чтобы настроить конфигурацию безопасности:

```bash
sudo -u opensearch OPENSEARCH_INITIAL_ADMIN_PASSWORD=Temets12345 /opt/opensearch/opensearch-tar-install.sh
```
Дожидаемся сообщения `Node 'temets-VirtualBox' initialized`, которое указывает указывает, что узел OpenSearch успешно инициализирован на нашем локальном сервере.

![alt2](/img/Screenshot%20from%202025-02-08%2021-41-51.png)

<!-- ```bash
[2025-02-08T21:41:05,957][INFO ][o.o.s.c.ConfigurationRepository] [temets-VirtualBox] Node 'temets-VirtualBox' initialized

``` -->

Создаем файл демона для автоматического управления процессом OpenSearch:

```bash
sudo nano /lib/systemd/system/opensearch.service
```

<details>

<summary>Содержимое файла opensearch.service:</summary>

```conf
[Unit]
Description=Opensearch
Documentation=https://opensearch.org/docs/latest
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
RuntimeDirectory=opensearch
PrivateTmp=true

Restart=on-failure
RestartSec=60s

WorkingDirectory=/opt/opensearch

User=opensearch
Group=opensearch

ExecStart=/opt/opensearch/bin/opensearch

StandardOutput=journal
StandardError=inherit

# Specifies the maximum file descriptor number that can be opened by this process
LimitNOFILE=65535

# Specifies the maximum number of processes
LimitNPROC=4096

# Specifies the maximum size of virtual memory
LimitAS=infinity

# Specifies the maximum file size
LimitFSIZE=infinity

# Not use SWAP
LimitMEMLOCK=infinity

# Disable timeout logic and wait until process is stopped
TimeoutStopSec=0

# Allow a slow startup before the systemd notifier module kicks in to extend the timeout
TimeoutStartSec=75

[Install]
WantedBy=multi-user.target
```

</details>

Обновим настройки systemd, чтобы система распознала новый сервис.

```bash
systemctl daemon-reload
```

### 2.1.2 Запуск Opensearch

Запустим настроенный нами демон OpenSearch

```bash
systemctl start opensearch
systemctl enable opensearch
```

Проверим статус запуска:

```bash
systemctl status opensearch
```

![alt](/img/Screenshot%20from%202025-02-08%2022-04-54.png)

<!-- ```bash
● opensearch.service - Opensearch
     Loaded: loaded (/usr/lib/systemd/system/opensearch.service; disabled; preset: enabled)
     Active: active (running) since Sat 2025-02-08 22:01:24 MSK; 10s ago
       Docs: https://opensearch.org/docs/latest
   Main PID: 10501 (java)
      Tasks: 24 (limit: 9445)
     Memory: 1.1G (peak: 1.1G)
        CPU: 14.317s
     CGroup: /system.slice/opensearch.service
             └─10501 /opt/opensearch/jdk/bin/java -Xshare:auto -Dopensearch.networkaddress.cache.ttl=60 -Dopensearch.networkaddress.cache.negative.ttl=10 -XX:+AlwaysPreTouch -Xss1m -Djava.a> 
```
-->


Проверим работоспособность демона OpenSearch выполняет GET-запрос к локальному серверу:

```bash
curl -X GET https://localhost:9200 -u 'admin:Temets12345' --insecure
```

![alt](/img/Screenshot%20from%202025-02-08%2022-13-19.png)

<!-- ```bash
{
  "name" : "temets-VirtualBox",
  "cluster_name" : "opensearch",
  "cluster_uuid" : "Ya5jYm0VTN-4Q3MGClra4w",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.18.0",
    "build_type" : "tar",
    "build_hash" : "99a9a81da366173b0c2b963b26ea92e15ef34547",
    "build_date" : "2024-10-31T19:08:39.157471098Z",
    "build_snapshot" : false,
    "lucene_version" : "9.12.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
``` -->

Примененяем конфиги плагина `opensearch-security`

```bash
sudo ./securityadmin.sh -cd ../../../config/opensearch-security/ -icl -nhnv   -cacert ../../../config/root-ca.pem   -cert ../../../config/kirk.pem   -key ../../../config/kirk-key.pem
```

<details>

<summary>Вывод команды:</summary>

![alt](/img/Screenshot%20from%202025-02-08%2022-28-58.png)

</details>

<!-- ```bash
Security Admin v7
Will connect to localhost:9200 ... done
Connected as "CN=kirk,OU=client,O=client,L=test,C=de"
OpenSearch Version: 2.18.0
Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ...
Clustername: opensearch
Clusterstate: YELLOW
Number of nodes: 1
Number of data nodes: 1
.opendistro_security index already exists, so we do not need to create one.
Populate config from /opt/opensearch/config/opensearch-security
Will update '/config' with ../../../config/opensearch-security/config.yml 
   SUCC: Configuration for 'config' created or updated
Will update '/roles' with ../../../config/opensearch-security/roles.yml 
   SUCC: Configuration for 'roles' created or updated
Will update '/rolesmapping' with ../../../config/opensearch-security/roles_mapping.yml 
   SUCC: Configuration for 'rolesmapping' created or updated
Will update '/internalusers' with ../../../config/opensearch-security/internal_users.yml 
   SUCC: Configuration for 'internalusers' created or updated
Will update '/actiongroups' with ../../../config/opensearch-security/action_groups.yml 
   SUCC: Configuration for 'actiongroups' created or updated
Will update '/tenants' with ../../../config/opensearch-security/tenants.yml 
   SUCC: Configuration for 'tenants' created or updated
Will update '/nodesdn' with ../../../config/opensearch-security/nodes_dn.yml 
   SUCC: Configuration for 'nodesdn' created or updated
Will update '/whitelist' with ../../../config/opensearch-security/whitelist.yml 
   SUCC: Configuration for 'whitelist' created or updated
Will update '/audit' with ../../../config/opensearch-security/audit.yml 
   SUCC: Configuration for 'audit' created or updated
Will update '/allowlist' with ../../../config/opensearch-security/allowlist.yml 
   SUCC: Configuration for 'allowlist' created or updated
SUCC: Expected 10 config types for node {"updated_config_types":["allowlist","tenants","rolesmapping","nodesdn","audit","roles","whitelist","actiongroups","config","internalusers"],"updated_config_size":10,"message":null} is 10 (["allowlist","tenants","rolesmapping","nodesdn","audit","roles","whitelist","actiongroups","config","internalusers"]) due to: null
Done with success

``` -->

<!-- ### 2.4 Проверяем работоспособность с новым паролем

```bash
temets@temets-VirtualBox:/opt/opensearch/plugins/opensearch-security/tools$ curl -X GET https://localhost:9200 -u 'admin:Admin12345' --insecure
```

```bash
{
  "name" : "temets-VirtualBox",
  "cluster_name" : "opensearch",
  "cluster_uuid" : "Ya5jYm0VTN-4Q3MGClra4w",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.18.0",
    "build_type" : "tar",
    "build_hash" : "99a9a81da366173b0c2b963b26ea92e15ef34547",
    "build_date" : "2024-10-31T19:08:39.157471098Z",
    "build_snapshot" : false,
    "lucene_version" : "9.12.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
``` -->

### 2.1.3 Переводим OpenSearch в режим кластера

Остановим демон OpenSearch, добавим параметры в настройки OpenSearch и сделаем его как одиночный узел с возможностью кластеризации.

```bash
systemctl stop opensearch
sudo nano /opt/opensearch/config/opensearch.yml
```
Узел `os-node01-temets-VirtualBox` будет принимать роль `master` для управления кластером и `data` для хранения и обработки запросов.

<details>

<summary>Содержимое настроек opensearch.yml:</summary>

```yml
# ------------------------------------ Node ------------------------------------
# Имя ноды:
node.name: os-node01-temets-VirtualBox
# Роли узла:
node.roles: [ master, data ]
#
# ---------------------------------- Network -----------------------------------
# Адрес узла:
network.host: 0.0.0.0
# Порт:
http.port: 9200
#
# ---------------------------------- Cluster -----------------------------------
# Имя кластера:
cluster.name: os_cluster
# Начальный список мастер-узлов:
cluster.initial_master_nodes: ["os-node01"]
#
# --------------------------------- Discovery ----------------------------------
# Поиск мастер-узлов:
discovery.seed_hosts: ["127.0.0.1"]
#
# ----------------------------------- Paths ------------------------------------
# Директория с данными:
path.data: /opt/opensearch/data
# Директория с логами:
path.logs: /var/log/opensearch
#
######## Start OpenSearch Security Demo Configuration ########
# WARNING: revise all the lines below before you go into production
plugins.security.ssl.transport.pemcert_filepath: esnode.pem
plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: esnode.pem
plugins.security.ssl.http.pemkey_filepath: esnode-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem
plugins.security.allow_unsafe_democertificates: true
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - CN=kirk,OU=client,O=client,L=test, C=de

plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-observability", ".opendistro-asynchronous-search-response*", ".opendistro-metadata-store"]
node.max_local_storage_nodes: 3
######## End OpenSearch Security Demo Configuration ########
```

</details>


Проверим работоспособность OpenSearch

```bash
curl -k -X GET https://localhost:9200 -u 'admin:Admin12345'
```

<details>

<summary>Вывод команды</summary>

![alt](/img/Screenshot%20from%202025-02-08%2023-31-31.png)


</details>

<!-- ```bash
{
  "name" : "os-node01-temets-VirtualBox",
  "cluster_name" : "os_cluster",
  "cluster_uuid" : "Ya5jYm0VTN-4Q3MGClra4w",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.18.0",
    "build_type" : "tar",
    "build_hash" : "99a9a81da366173b0c2b963b26ea92e15ef34547",
    "build_date" : "2024-10-31T19:08:39.157471098Z",
    "build_snapshot" : false,
    "lucene_version" : "9.12.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
``` -->

Проверим состояние кластера.

```bash
curl -X GET https://localhost:9200/_cat/master?pretty -u 'admin:Admin12345' --insecure
```

![alt](/img/Screenshot%20from%202025-02-08%2023-33-38.png)

<!-- ```bash
uw6JCiJ-Qc2S2nvuSqWHbw 10.0.2.15 10.0.2.15 os-node01-temets-VirtualBox
``` -->

## 2.2 OpenSearch-Dashboards

### 2.2.1 Установка OpenSearch-Dashboards

Скачаем OpenSearch-Dashboards с официального сайта (https://opensearch.org/downloads.html) и разархивируем его в `/opt/opensearch-dashboards/`

Даем право владельца `opensearch` для каталогоа `/opt/opensearch-dashboards`

```bash
sudo chown -R opensearch:opensearch /opt/opensearch-dashboards
```

Создаем файл демона для автоматического управления процессом OpenSearch-Dashboards:

```bash
sudo nano /lib/systemd/system/opensearch_dashboards.service
```

<details>

<summary>Содержимое файла opensearch_dashboards.service:</summary>

```conf
[Unit]
Description=Opensearch_dashboards
Documentation=https://opensearch.org/docs/latest
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
RuntimeDirectory=opensearch_dashboards
PrivateTmp=true

WorkingDirectory=/opt/opensearch-dashboards

User=opensearch
Group=opensearch

ExecStart=/opt/opensearch-dashboards/bin/opensearch-dashboards

StandardOutput=journal
StandardError=inherit

# Specifies the maximum file descriptor number that can be opened by this process
LimitNOFILE=65535

# Specifies the maximum number of processes
LimitNPROC=4096

# Specifies the maximum size of virtual memory
LimitAS=infinity

# Specifies the maximum file size
LimitFSIZE=infinity

# Disable timeout logic and wait until process is stopped
TimeoutStopSec=0

# Allow a slow startup before the systemd notifier module kicks in to extend the timeout
TimeoutStartSec=75

[Install]
WantedBy=multi-user.target
```

### 2.2.2 Запуск OpenSearch-Dashboards

</details>

Запустим настроенный нами демон OpenSearch-Dashboards

```bash
systemctl start opensearch_dashboards
systemctl enable opensearch_dashboards
```

Проверим статус запуска:

```bash
systemctl status opensearch_dashboards
```

![alt](/img/Screenshot%20from%202025-02-08%2023-58-00.png)

<!-- ```bash
temets@temets-VirtualBox:~/Downloads$ systemctl status opensearch_dashboards
● opensearch_dashboards.service - Opensearch_dashboards
     Loaded: loaded (/usr/lib/systemd/system/opensearch_dashboards.service; enabled; preset: enabled)
     Active: active (running) since Sat 2025-02-08 23:55:29 MSK; 28s ago
       Docs: https://opensearch.org/docs/latest
   Main PID: 23434 (node)
      Tasks: 11 (limit: 9445)
     Memory: 327.2M (peak: 327.6M)
        CPU: 12.816s
     CGroup: /system.slice/opensearch_dashboards.service
             └─23434 /opt/opensearch-dashboards/node/bin/node /opt/opensearch-dashboards/src/cli/dist

``` -->

Можно теперь перейти на localhost:5601 и увидеть стартовый экран OpenSearch-Dashboards.

![alt](/img/Screenshot%20from%202025-02-09%2000-03-01.png)
 
## 2.3 Logstash

### 2.3.1 Установка Logstash

Скачаем Logstash с официального сайта (https://opensearch.org/downloads.html) и разархивируем его в `/opt/logstash/`

Даем право владельца `logstash` для каталогоа `/opt/logstash`

```bash
sudo chown -R logstash:logstash /opt/logstash
```

Даем право владельца `logstash` для каталогоа логов `/var/log/logstash`

```bash
sudo chown -R logstash /var/log/logstash
```

Создаем каталог для файлов pipelines и создадим каталог для логов

```bash
sudo mkdir /opt/logstash/config/conf.d
sudo mkdir /var/log/logstash
```

Создаем файл демона для автоматического управления процессом Logstash:

```bash
sudo nano /lib/systemd/system/logstash.service
```
<details>

<summary>Содержимое файла logstash.service:</summary>

```conf
[Unit]
Description=logstash

[Service]
Type=simple
User=logstash
Group=logstash

ExecStart=/opt/logstash/bin/logstash "--path.settings" "/opt/logstash/config"
Restart=always
WorkingDirectory=/opt/logstash
Nice=19
LimitNOFILE=16384

# When stopping, how long to wait before giving up and sending SIGKILL?
# Keep in mind that SIGKILL on a process can cause data loss.
TimeoutStopSec=75

[Install]
WantedBy=multi-user.target
```

</details>


Зададим путь к базе данных и логам Logstash

```bash
sudo nano /opt/logstash/config/logstash.yml
```

<summary>Содержимое файла logstash.yml:</summary>

```yml
# Which directory should be used by logstash and its plugins
# for any persistent needs. Defaults to LOGSTASH_HOME/data
#
path.data: /opt/logstash/data

# Set the pipeline event ordering. Options are "auto" (the default)
pipeline.ordered: auto

# log.level: info
path.logs: /var/log/logstash
```

</details>


### 2.3.2 Запуск Logstash


Запустим настроенный нами демон и проверим статус запуска.

```bash
systemctl start logstash
systemctl enable logstash
```

Проверим статус запуска:

```bash
systemctl status logstash
```

![alt](/img/Screenshot%20from%202025-02-09%2000-54-29.png)

<!-- ```bash
● logstash.service - logstash
     Loaded: loaded (/etc/systemd/system/logstash.service; enabled; preset: enabled)
     Active: active (running) since Sun 2025-02-09 00:26:13 MSK; 20s ago
   Main PID: 33261 (java)
      Tasks: 25 (limit: 9445)
     Memory: 340.3M (peak: 341.3M)
        CPU: 33.492s
     CGroup: /system.slice/logstash.service
             └─33261 /opt/logstash/jdk/bin/java -Xms1g -Xmx1g -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djruby.compile.invokedynamic=true -XX:+HeapDumpOnOutOfMemoryError -Djava.securi>
``` -->

# 3. Сбор данных

## 3.1 Настройка конфигурации

В качестве данных для чтения данных был выбран датасет Web log access dataset (https://www.kaggle.com/datasets/sanjeevsahu/web-log-access-dataset) из логов веб-сервера, который содержит записи о запросах пользователей к веб-сайту.

Настроим Logstash для чтения данных из файла датасета, используя File Input Plugin. Создадим файл конфигурации access_log_pipeline.conf:

```bash
sudo nano /opt/logstash/config/conf.d/access_log_pipeline.conf
```

Модуль File Input:

```conf
input {
	file {
		path => "/home/temets/projects/volgablob-task/access_log_Jul95.txt"
		start_position => "beginning"
		codec => "plain"
		sincedb_path => "/dev/null"
	}
}
```

Реализуем парсинг событий лога используя Grok Filter Plugin. 

Числовые данные были преобразованны с помощью фильтра `mutate` для удобного анализа и работы со статистическими операциями.

Временные метки `timestamp` были преобразованы в формат `@timestamp`, чтобы данные хранились в хронологическом порядке

Модуль Grok Filter:

```conf
filter {
  grok {
    match => { "message" => "(%{IP:source.ip}|%{HOSTNAME:source.name}) %{USER:user.id} %{USER:user.name} \[%{HTTPDATE:timestamp}\] \"%{WORD:verb} %{DATA:request}(?: HTTP/%{NUMBER:httpversion})?\" %{NUMBER:response} (?:%{NUMBER:bytes}|-)" }
  }
  mutate {
    convert => { 
        "bytes" => "integer"
        "response" => "integer"
        "httpversion" => "float"
    }
  }
  date {
    match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    target => "@timestamp"
  }
}
```

Настраиваем вывод данных в OpenSearch. Для отладки будем выводить результаты в консоль с помощью `stdout`, также отключим проверку SSL-сертификатов.

Если в процессе парсинга данных возникнит ошибка (метка `_grokparsefailure`), то данные отправлятся в отдельный индекс. В остальных случаях будет создаваться индекс с припиской даты.

Модуль OpenSearch Output:

```conf
output {
 if "_grokparsefailure" in [tags] {
  opensearch {
   hosts       => "https://localhost:9200"
   user        => "admin"
   password    => "Admin12345"
   index       => "logstash-logs_failure"
   ssl_certificate_verification => false
  }
 }
 else {
  opensearch {
   hosts       => "https://localhost:9200"
   user        => "admin"
   password    => "Admin12345"
   index       => "logstash-logs-%{+YYYY.MM.dd}"
   ssl_certificate_verification => false
  }
 }
 stdout { codec => rubydebug }
}
```

## 3.2 Запуск Logstash с pipeline 

Проверим работу Logstash с нашим pipeline.

```bash
sudo /opt/logstash/bin/logstash -f /opt/logstash/config/conf.d/access_log_pipeline.conf
```

Получаем обработанные данные в формате JSON. 

Пример одной записи:

![alt text](/img/Screenshot%20from%202025-02-09%2013-13-16.png)

<!-- ```json
{
          "event" => {
        "original" => "134.87.29.12 - - [01/Jul/1995:01:56:03 -0400] \"GET /shuttle/countdown/count.gif HTTP/1.0\" 200 40310"
    },
          "bytes" => 40310,
       "response" => 200,
     "@timestamp" => 1995-07-01T05:56:03.000Z,
            "log" => {
        "file" => {
            "path" => "/home/temets/projects/volgablob-task/access_log_Jul95.txt"
        }
    },
    "httpversion" => 1.0,
        "message" => "134.87.29.12 - - [01/Jul/1995:01:56:03 -0400] \"GET /shuttle/countdown/count.gif HTTP/1.0\" 200 40310",
       "sourceip" => "134.87.29.12",
        "request" => 0,
      "timestamp" => "01/Jul/1995:01:56:03 -0400",
           "host" => {
        "name" => "temets-VirtualBox"
    },
       "@version" => "1",
           "verb" => "GET",
       "username" => "-",
         "userid" => "-"
}
``` -->

Проверим подачу данных в OpenSearch. Для отладки пока будем игнорировать проверку SSL-сертификатов параметром `-k`

```bash
curl -X GET https://localhost:9200/logstash-logs*/_search?pretty -u 'admin:Admin12345' -k
```
Opensearch выдал 10 записей из 10000. Запрос занял 64 миллисекунды без каких либо ошибок.

![alt text](img/Screenshot%20from%202025-02-09%2013-39-37.png)

<!-- ```json
  "took" : 64,
  "timed_out" : false,
  "_shards" : {
    "total" : 2,
    "successful" : 2,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 10000,
      "relation" : "gte"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "logstash-logs-1995.07.01",
        "_id" : "G78v6pQBPBWeWmpSL4RU",
        "_score" : 1.0,
        "_source" : {
          "@timestamp" : "1995-07-01T04:00:09.000Z",
          "bytes" : 4085,
          "verb" : "GET",
          "sourceip" : "199.120.110.21",
          "timestamp" : "01/Jul/1995:00:00:09 -0400",
          "message" : "199.120.110.21 - - [01/Jul/1995:00:00:09 -0400] \"GET /shuttle/missions/sts-73/mission-sts-73.html HTTP/1.0\" 200 4085",
          "event" : {
            "original" : "199.120.110.21 - - [01/Jul/1995:00:00:09 -0400] \"GET /shuttle/missions/sts-73/mission-sts-73.html HTTP/1.0\" 200 4085"
          },
          "request" : 0,
          "httpversion" : 1,
          "log" : {
            "file" : {
              "path" : "/home/temets/projects/volgablob-task/access_log_Jul95.txt"
            }
          },
          "@version" : "1",
          "response" : "200",
          "host" : {
            "name" : "temets-VirtualBox"
          },
          "username" : "-",
          "userid" : "-"
        }
      }
      ...
  }
``` -->

# 4. Визуализация данных

## 4.1 Шаблон индексов

OpenSearch Dashboards использует индексные паттерны(Index pattern) для поиска и фильтрации нужных данных и нужны для построения визуализации, графики или дашборды на основе данных.

Это шаблон индексов, который может включать один или несколько индексов сортируя их по дате. Любое поле, имеющее формат «дата», может быть использовано в качестве даты. 

Например, logstash-logs-* будет подходить для всех индексов, начинающихся с logstash-logs-.

Чтобы создать индексные паттерны перейдем:

`Management` -> `Dashboards Managements` -> `Index patterns`

Нажимаем на `Create index pattern`

На шаге 1 введем в строке имени шаблона название индекса `logstash-logs-*`

На шаге 2 параметром сортировки данных в шаблоне выберем `@timestamp`

![alt text](/img/Screenshot%20from%202025-02-09%2013-39-36.png)

## 4.2 Просмотр индексов

В OpenSearch Dashboards можно также просмотреть все доступные индексы и их статус.

Чтобы просмотреть индексы перейдем:

`Management` -> `Index Managements` -> `Indexes`

Мы видим 3 индекса, 1 из которых содержит неотфильтрованные документы. Индексы `logstash-logs-*` имеют состояние `Yellow`, это значит, что индексы  доступны для чтения, но реплики не настроены, о чем так же говорит столбец `Replicas`. 

![alt text](/img/Screenshot%20from%202025-02-09%2016-38-51.png)

## 4.3 Отображение данных

Перейдем на страницу отображения данных:

`OpenSearch Dashboards` -> `Discover`

В раздел `Discover` выбирам нужный индексный шаблон, в нем будут отображаться доступные сообщения. Вы сможете развернуть содержимое сообщения и заметить, что заголовки ключей из JSON-просообщения преобразованы в одноименные поля, а значения этих ключей стали значениями полей.

Настроим свою таблицу, добавив фильтры для всех доступных полей из документа и ограничив поиск с 1 Июля 1995 по 3 Июля 1995. Эти настройки можно сохранять, чтобы в будущем быстро возвращаться к ним.

![alt](/img/Screenshot%20from%202025-02-09%2018-18-59.png)

## 4.4 Создание дашбордов

Дашборды - это сборник различных визуализаций, которые отображают данные из кластера OpenSearch. Дашборды позволяют объединить несколько элементов, например, гистограммы, линейные графики, карты, таблицы для того, чтобы легко отслеживать важные метрики и события в системе.

Чтобы просмотреть и создать дашборд перейдем:

`OpenSearch Dashboards` -> `Dashboard`

Нажмем кнопку `Create new dashboard`. После этого откроется пустой дашборд, куда можно добавлять визуализации. Создадим несколько визуализаций.

![alt](/img/Screenshot%20from%202025-02-09%2021-01-44.png)

### 4.4.1 Линейные диаграммы 

Создадим линейную диаграмму, которая будет отображать количество запросов во времени.

Также добавим пороговое значение в 2000 запросов, которое будет отображаться на графике в виде линии.

![alt](/img/Screenshot%20from%202025-02-09%2020-55-38.png)

Создадим еще одну линейную диаграмму, которая будет отображать сумму байтов за день, переданных в ответе от сервера во времени.

![alt](/img/Screenshot%20from%202025-02-09%2020-59-18.png)

### 4.4.2 Колоночные диаграммы 

Создадим горизонтальную колончатую диаграмму, которая будет отображать топ 5 ресурсов на сервере, к которым обращались.


![alt](/img/Screenshot%20from%202025-02-09%2020-59-49.png)

### 4.4.3 Круговые диаграммы 

Создадим круговую диаграмму, которая будет отображать топ 5 IPv4-адресов клиента (или устройств), которые отправили запрос к серверу.

![alt](/img/Screenshot%20from%202025-02-09%2020-57-15.png)

Создадим такую же диаграмму но для IPv6-адресов.

![alt](/img/Screenshot%20from%202025-02-09%2020-58-02.png)

### 4.4.4 Числовые панели

Создадим несколько числовых панелей. Первая метрика будет отображать количество записей с 4xx HTTP-статусом ошибки клиента. Для этого настроим фильры поля `response`, чтобы исключить появляение других HTTP-статусов.

![alt](/img/Screenshot%20from%202025-02-09%2020-58-45.png)

Вторая метрица покажет количество необработанных документов, которые попали в индекс `logstash-logs_failure`.

![alt](/img/Screenshot%20from%202025-02-09%2021-01-25.png)

Последняя числовые панели будет представлять таблицу из HTTP-методов и количества их использований во времени.

![alt](/img/Screenshot%20from%202025-02-09%2021-00-18.png)

### 4.4.5 Итоговый дашборд

Расставим визуализации на дашборд, изменим их размеры и поставим временой фильр с 1 Июля 1995 по 3 Июля 1995 для того, чтобы результаты нагляднее отображались.

![alt](/img/Screenshot%20from%202025-02-09%2020-54-38.png)


> [!NOTE]
> Датасет преимущественно состоит из однотипных записей с ограниченным числом уникальных значений, что затрудняет создание информативных и практичных визуализаций. Однако в данной работе это не было основной целью. 


# 5. Отчет по работе

В процессе выполнения работы возникникли некоторые сложности:

1. Формирование Pipeline для Logstash, а точнее Grok-фильтров. Помогли сервис [GrokDebugger](https://grokdebugger.com/) и статья [Grok patterns](https://www.alibabacloud.com/help/en/sls/user-guide/grok-patterns).
2. Решение аномалий в датасете, когда запись очевидно с ошибкой. Помог вопрос с [форума elastic](https://discuss.elastic.co/t/what-is-the-best-way-to-handle-grokparsefailure-errors/106092/3).
3. Построение дашбордов. Помогло небольшое [видео на YouTube](https://www.youtube.com/watch?v=Df-g3tYu3w4&ab_channel=AnthonyDerbah).
