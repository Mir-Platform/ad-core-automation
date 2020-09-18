#!/usr/bin/env python3

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import sys
import argparse
import ntpath
import yaml


def create_parser():
    parser = argparse.ArgumentParser(
        description='',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('-a', '--ad',
                        type=str,
                        default='domain.ru',
                        help='AD URL')

    parser.add_argument('-b', '--ad_branch',
                        type=str,
                        default='OU=Projects,DC=test,DC=ru',
                        help='AD branch filter')

    parser.add_argument('-u', '--user',
                        type=str,
                        required=True,
                        help='AD administrator user')

    parser.add_argument('-p', '--passwd',
                        type=str,
                        required=True,
                        help='AD administrator user')

    parser.add_argument('-f', '--file',
                        type=str,
                        required=True,
                        help='project model yaml, must endswith _meta.yaml')

    return parser


def parse_ad_branch(connection, ad_branch):
    """
    Создает словарь содержимого целевой ветви дерева
    :param connection: сессия подключения к AD
    :param ad_branch: str 'OU=Projects,dc=test,dc=ru'
    :return: dict {'project': 
        {'dn': 'OU=project,DC=test,DC=ru', 
         'groups': 
            {'project-developers': 
                {'members': ['user1', 'user2', 'userN'],
            'dn': 'CN=project-developers,OU=Projects,DC=test,DC=ru'}, ...
        }
    """

    ou_data = {}

    connection.search(
        search_base=ad_branch,
        search_filter='(objectclass=organizationalUnit)',
        search_scope=SUBTREE,
        attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES],
        size_limit=0
    )

    # Получение имени базового элемента ветки
    listed_element = ad_branch.split(',')[0].split('=')[1]

    for entry in connection.entries:
        # Добавление в OU в дату за исключением базового элемента ветки
        if entry.name.value not in ou_data and entry.name.value != listed_element:
            ou_data[entry.name.value] = {}
            ou_data[entry.name.value]['groups'] = {}
            ou_data[entry.name.value]['dn'] = entry.entry_dn

    # получение содержимого групп
    for unit in ou_data:
        connection.search(
            search_base=ou_data[unit]['dn'],
            search_filter='(objectclass=group)',
            search_scope=SUBTREE,
            attributes=['member', 'name'],
            size_limit=0
        )

        for entry in connection.entries:
            if 'groups' not in ou_data[unit]:
                ou_data[unit]['groups'] = {}
            if entry.name.value not in ou_data[unit]['groups']:
                ou_data[unit]['groups'][entry.name.value] = {'members': [], 'dn': entry.entry_dn}

            # превращение полных имен из members в sAMAccountName
            for member in entry.member.values:
                connection.search(
                    search_base='dc=test,dc=ru',
                    search_filter=f'(distinguishedName={member})',
                    attributes=['sAMAccountName'],
                    size_limit=0
                )

                user_sAMAccountName = connection.entries[0].sAMAccountName.values[0]
                ou_data[unit]['groups'][entry.name.value]['members'].append(user_sAMAccountName)

    return ou_data


def create(connection, ad_branch, ad_unit_type):
    """
    Создает объект в AD
    :param connection: сессия подключения к AD
    :param ad_branch: str 'OU=Projects,dc=test,dc=ru'
    :param ad_unit_type: str ['group', 'organizationalUnit']
    :return: None
    """
    connection.add(ad_branch, ad_unit_type)

    print('CREATE', connection.result['description'], ad_branch)


def yaml_read(path):
    """
    Простая функция чтения yaml файла
    :param path: path to yaml file
    :return: project map dictionary
    """
    with open(path, 'r') as project_model:
        try:
            model = yaml.safe_load(project_model)
        except yaml.YAMLError as exc:
            print(exc)

        return model


def user_merge_in_groups(connection, project_name, project_map, ad_branch):
    """
    Функция сравнивает состояние групп в AD и в карте проекта
     на основании этого добавляет или удаляет пользователей.
    :param connection: сессия подключения к AD
    :param project_name: str имя проекта
    :param project_map: dict карта проекта
    :param ad_branch: str 'OU=Projects,dc=test,dc=ru'
    :return: merge_log
    """
    ad_branch_dictionary = parse_ad_branch(connection, ad_branch)

    merge_log = {
        'delete': [],
        'add': []
    }

    # Проверка защиты обработки модели
    if project_map['READY']:
        if project_map['TEAM'] and \
                project_map['TEAM']['USER_LOCATION'] == 'ldap':
            for role in project_map['TEAM']['ROLES']:
                users_in_role = project_map['TEAM']['ROLES'][role]

                sec_group_name = f'rb-{project_name}-{role}'
                sec_group_path = f'CN={sec_group_name},OU={project_name},{ad_branch}'

                # Создание security-groups
                if sec_group_name not in ad_branch_dictionary[project_name]['groups']:
                    create(connection, sec_group_path, 'group')
                    ad_branch_dictionary = parse_ad_branch(connection, ad_branch)

                # Удаление пользователей, отсутствующих в карте проекта, но присутствующих в AD
                if project_name in ad_branch_dictionary:
                    for user in ad_branch_dictionary[project_name]['groups'][sec_group_name]['members']:
                        if user not in users_in_role:
                            merge_log['delete'].append(user)
                            search_filter = f'(&(objectclass=person)(sAMAccountName={user}))'
                            connection.search(
                                search_base='DC=test,DC=ru',
                                search_filter=search_filter,
                                search_scope=SUBTREE,
                                size_limit=0
                            )
                            user_cn = connection.entries[0].entry_dn
                            connection.extend.microsoft.remove_members_from_groups([user_cn], [sec_group_path])
                            # print(connection.result)

                # Добавление пользователей в security-groups
                for user in users_in_role:
                    print(user)
                    if user not in ad_branch_dictionary[project_name]['groups'][sec_group_name]['members']:
                        merge_log['add'].append(user)
                        search_filter = f'(&(objectclass=person)(sAMAccountName={user}))'
                        connection.search(
                            search_base='DC=test,DC=ru',
                            search_filter=search_filter,
                            search_scope=SUBTREE,
                            size_limit=0
                        )
                        user_cn = connection.entries[0].entry_dn
                        connection.extend.microsoft.add_members_to_groups([user_cn], [sec_group_path])
                        # print(connection.result)

    return merge_log


def main():
    parser = create_parser()
    parser_namespace = parser.parse_args(sys.argv[1:])

    ad = parser_namespace.ad
    ad_user = parser_namespace.user
    ad_passwd = parser_namespace.passwd
    ad_branch = parser_namespace.ad_branch
    project_model_path = parser_namespace.file

    project_name = ntpath.basename(project_model_path).replace('_meta.yaml', '')

    server = Server(ad, use_ssl=True, get_info=ALL)

    connection = Connection(server,
                            user=f'{ad}\\' + ad_user,
                            password=ad_passwd,
                            authentication=NTLM,
                            auto_bind=True)

    ad_branch_dictionary = parse_ad_branch(connection, ad_branch)
    project_map = yaml_read(project_model_path)

    # Создаем проектный OU, если отсутствует в AD
    if project_name not in ad_branch_dictionary:
        create(connection, f'OU={project_name},{ad_branch}', 'organizationalUnit')

    merge_log = user_merge_in_groups(connection, project_name, project_map, ad_branch)

    print(merge_log)

    connection.unbind()


if __name__ == "__main__":
    main()
