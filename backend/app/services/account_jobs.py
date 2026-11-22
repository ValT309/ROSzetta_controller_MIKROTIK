"""Local RouterOS account operations for the persistent management queue.

No passwords in plans, results or exception text. The caller owns encryption and
queue persistence. Every possible remote write is followed by a metadata check.
"""
import ipaddress
import re

ACTIONS = {'user-add', 'user-password', 'user-delete', 'user-groups'}
NAME = re.compile(r'[A-Za-z0-9_.-]{1,32}\Z')

class AccountBlocked(ValueError):
    """No remote write was attempted."""

class AccountUnconfirmed(ValueError):
    """A remote write may have taken effect."""


def normalize_address(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise AccountBlocked('Некорректный список разрешённых адресов')
    try:
        return ','.join(sorted({str(ipaddress.ip_network(s.strip(), strict=False)) for s in value.split(',') if s.strip()}))
    except ValueError:
        raise AccountBlocked('Адрес: IP или подсеть, через запятую') from None


def normalize_request(p):
    if not isinstance(p, dict) or not isinstance(p.get('action'),str) or p.get('action') not in ACTIONS:
        raise AccountBlocked('Неизвестная операция с пользователями')
    action = p['action']
    ids = p.get('ids')
    if not isinstance(ids, list) or not 1 <= len(ids) <= 200 or any(type(i) is not int or i <= 0 for i in ids):
        raise AccountBlocked('Выберите от 1 до 200 устройств')
    ids = list(dict.fromkeys(ids))
    if action == 'user-groups':
        return action, ids, {}, '', False
    if p.get('confirmed') is not True:
        raise AccountBlocked('Подтвердите операцию')
    username = p.get('username', '')
    if not isinstance(username, str) or not NAME.fullmatch(username.strip()):
        raise AccountBlocked('Логин: 1–32 символа, латиница, цифры, _ . -')
    spec = {'username': username.strip()}
    password = p.get('password', '') if action != 'user-delete' else ''
    if action != 'user-delete' and (not isinstance(password, str) or not 8 <= len(password) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in password)):
        raise AccountBlocked('Пароль: 8–128 символов, без управляющих символов')
    if action == 'user-add':
        group = p.get('group', '')
        if not isinstance(group, str) or not NAME.fullmatch(group.strip()):
            raise AccountBlocked('Некорректное имя группы')
        spec.update(group=group.strip(), address=normalize_address(p.get('address', '')), update_existing=p.get('update_existing') is True)
    return action, ids, spec, password, p.get('allow_plain') is True


def truth(v):
    return v is True or str(v).lower() in ('true', 'yes', '1')


def named(rows, name):
    matches = [r for r in rows if r.get('name') == name]
    if len(matches) > 1:
        raise AccountBlocked('Найдены неоднозначные записи пользователя или группы')
    return matches[0] if matches else None


def user_operation(api, action, controller, spec, password, controller_password_matches=False):
    """Reads/preconditions first; return fixed safe diagnostics. No secret in result."""
    if action == 'user-groups':
        groups = sorted({str(r['name']) for r in api.path('user', 'group') if r.get('name')})
        return {'detail': 'Группы: ' + (', '.join(groups) or 'нет'), 'account_groups': groups}
    username = spec['username']
    users = api.path('user')
    rows = list(users)
    existing = named(rows, username)
    if action == 'user-add' and existing and not spec['update_existing']:
        return {'detail': 'Пользователь уже существует — пропущен', 'account_status': 'skipped'}
    if action != 'user-add' and not existing:
        return {'detail': 'Пользователь отсутствует — пропущен', 'account_status': 'skipped'}
    if username == controller:
        # Same credential already authenticated; safe no-op, never rewrite it.
        if existing and controller_password_matches and (action=='user-password' or (action=='user-add' and existing.get('group')==spec['group'] and (not spec['address'] or normalize_address(str(existing.get('address') or ''))==spec['address']))):
            return {'detail': 'Учётная запись контроллера уже соответствует запросу — без изменений', 'account_status': 'skipped'}
        raise AccountBlocked('Учётная запись текущего подключения ROSzetta защищена. Смена данных — через отдельную процедуру подключения')
    if existing and not existing.get('.id'):
        raise AccountBlocked('Не удалось определить ID пользователя')
    if action == 'user-add':
        groups = list(api.path('user', 'group'))
        if not named(groups, spec['group']):
            raise AccountBlocked('Группа не найдена — сначала создайте её на устройстве')
    if existing and existing.get('group') == 'full' and (action == 'user-delete' or (action == 'user-add' and spec['group'] != 'full')):
        others = [r for r in rows if r.get('group') == 'full' and r.get('.id') != existing.get('.id') and not truth(r.get('disabled')) and not truth(r.get('expired'))]
        if not others:
            raise AccountBlocked('Нельзя удалить или понизить последнего действующего пользователя группы full')
    # From here on all exceptions are ambiguous: never auto-replay a write.
    try:
        if action == 'user-delete':
            users.remove(existing['.id'])
        elif action == 'user-password':
            users.update(**{'.id': existing['.id'], 'password': password})
        elif action == 'user-add':
            params = {'password': password, 'group': spec['group']}
            if spec['address']:
                params['address'] = spec['address']
            if existing:
                users.update(**{'.id': existing['.id'], **params})
            else:
                users.add(name=username, **params)
        else:
            raise RuntimeError('unknown action')
        after = named(list(api.path('user')), username)
        if action == 'user-delete':
            if after is not None:
                raise RuntimeError('not deleted')
        else:
            if not after or (existing and after.get('.id') != existing.get('.id')):
                raise RuntimeError('account not confirmed')
            if action == 'user-add' and after.get('group') != spec['group']:
                raise RuntimeError('group mismatch')
            expected_address = spec.get('address') or (str(existing.get('address') or '') if existing else '')
            if normalize_address(str(after.get('address') or '')) != normalize_address(expected_address):
                raise RuntimeError('address mismatch')
            if action == 'user-password' and after.get('group') != existing.get('group'):
                raise RuntimeError('group changed')
    except Exception:
        raise AccountUnconfirmed('Запись могла выполниться; проверьте фактическое состояние пользователя и пароль перед повтором') from None
    if action == 'user-delete':
        return {'detail': 'Пользователь удалён, отсутствие подтверждено', 'account_status': 'deleted'}
    detail = 'Пароль изменён' if action == 'user-password' else 'Пользователь обновлён' if existing else 'Пользователь создан'
    return {'detail': detail + '; RouterOS принял команду, запись проверена (вход новым паролем отдельно не проверялся)', 'account_status': 'updated' if existing else 'created'}
