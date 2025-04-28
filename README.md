# Тестовое задание
Выполнил: Дмитриев Дмитрий Игоревич

## DB DDL
### Создание таблицы
```sql
create table guid
(
    guid          varchar,
    refresh_token varchar,
    email         varchar
);
```

### Функция получения электронной почты пользователя по guid
```sql
create function get_email_by_guid(_guid character varying) returns character varying
    security definer
    language plpgsql
as
$$
DECLARE
    _res varchar;
BEGIN
    SELECT g.email
    FROM public.guid g
    WHERE g.guid = _guid
    INTO _res;

    RETURN _res;
END;
$$;
```

### Функция получения refresh токена по guid
```sql
create function get_refresh_token_by_guid(_guid character varying) returns character varying
    security definer
    language plpgsql
as
$$
DECLARE
    _res varchar;
BEGIN
    SELECT g.refresh_token
    FROM public.guid g
    WHERE g.guid = _guid
    INTO _res;

    RETURN _res;
END;
$$;
```

### Процедура сета refresh токена по guid
```sql
create procedure set_refresh_token_by_guid(_guid character varying, _refresh_token character varying)
    security definer
    language plpgsql
as
$$
BEGIN
    UPDATE public.guid
    SET refresh_token = _refresh_token
    WHERE guid = _guid;
END;
$$;
```