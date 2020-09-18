Скрипт для автоматизации создания OU и SecurityGroup в AD

Скрипт обрабатывает файлы описания проектов в формате yaml.
Обрабатываемая структура файла:
```
---
READY: True  # Защита от "дурака", если не True, то автоматизация проигнорирует весь файл

TEAM:
  # Описание состава команды (роли)
  USER_LOCATION: ldap  # обязательное значение
  ROLES:
    role1:
      - user1
      - user2
    role2:
      - user3
      - user1
```
Пример запуска: 
```
pip install -r requirements.txt
```
```
./run.py -a domain.ru -b "OU=Projects" -u test -p pass -f ./testproject_meta.yaml
```
```
arguments:
  -h, --help            help
  -a, --ad              AD URL (default: test.ru)
  -b, --ad_branch       AD branch filter (default:
                            OU=Projects)
  -u, --user            AD administrator user
  -p, --passwd          AD administrator user
  -f, --file            project model yaml, must endswith _meta.yaml
```
На основании карты testproject_meta.yaml в AD будет создан OU testproject.
В нем созданы SecurityGroups rb-testproject-role1 и rb-testproject-role2 с соответствующими пользователями в них.

Скрипт отслеживает разницу пользователей в роли карты проекта с пользователями в SecurityGroup AD, 
добавляет и удаляет их в AD, согласно с изменениями в testproject_meta.yaml. 
Скрипт не удаляет группы автоматически, т.к. это опасная операция, которая не должна совершаться автоматикой. 
