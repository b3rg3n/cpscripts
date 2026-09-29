import json
import hmac
import hashlib
from decimal import Decimal, ROUND_HALF_UP
from typing import Any


def format_value(value: Any) -> str | None:
    """
    Приводит значение к строке согласно правилам подписи.

    - None -> исключается
    - "" -> исключается
    - bool -> true / false
    - Decimal/float -> всегда 2 знака после точки
    - int -> обычное целое число

    ВАЖНО:
    amount и другие decimal-поля желательно передавать как Decimal
    либо обрабатывать отдельно при чтении JSON.
    """

    if value is None:
        return None

    if isinstance(value, str):
        if value == "":
            return None
        return value

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, Decimal):
        rounded = value.quantize(
            Decimal("0.01"),
            rounding=ROUND_HALF_UP
        )
        return f"{rounded:.2f}"

    if isinstance(value, float):
        decimal_value = Decimal(str(value)).quantize(
            Decimal("0.01"),
            rounding=ROUND_HALF_UP
        )
        return f"{decimal_value:.2f}"

    if isinstance(value, int):
        return str(value)

    return str(value)


def collect_values(
    obj: Any,
    values: list[str],
    key: str | None = None
) -> None:
    """
    Рекурсивно собирает конечные значения из JSON.

    Поле signature полностью игнорируется.
    Вложенные объекты (user, billingAddress, userData и т.д.)
    разворачиваются до конечных значений.
    """

    if isinstance(obj, dict):
        for child_key, child_value in obj.items():
            if child_key == "signature":
                continue

            collect_values(
                child_value,
                values,
                key=child_key
            )

    elif isinstance(obj, list):
        for item in obj:
            collect_values(item, values, key=key)

    else:
        # По нашим рабочим запросам amount является decimal,
        # даже если в JSON написано просто 500.
        if key == "amount" and isinstance(obj, (int, float, Decimal)):
            value = Decimal(str(obj)).quantize(
                Decimal("0.01"),
                rounding=ROUND_HALF_UP
            )
            formatted = f"{value:.2f}"
        else:
            formatted = format_value(obj)

        if formatted is not None:
            values.append(formatted)


def generate_signature(
    payload: dict,
    private_key: str
) -> tuple[str, str]:
    """
    Возвращает:
    1. HMAC-SHA256 signature в lowercase hex
    2. Строку, которая была подписана
    """

    values: list[str] = []

    collect_values(payload, values)

    # ВАЖНО: сортируем ЗНАЧЕНИЯ, а не названия параметров.
    # Python сортирует строки case-sensitive.
    values.sort()

    string_to_sign = "|".join(values)

    signature = hmac.new(
        private_key.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return signature, string_to_sign


if __name__ == "__main__":
    PRIVATE_KEY = "2222222222" # тут должен быть приватный ключ из ноя

    # ниже вставляем тело запроса для генерации подписи
    payload = {
        "project": "111111", # тут должен быть id проекта из ноя
        "user": {
            "id": "12345678k",
            "email": "tester11@mail.ru",
            "name": "John Smith",
            "customerGroup": "trusted",
            "phone": "265997000042",
            "dateOfBirth": "2004-07-28T12:44:24.6305652Z"
        },
        "billingAddress": {
            "addressLine1": "7, Sunny street",
            "addressLine2": "Office 3",
            "city": "Limassol",
            "postalCode": "4141",
            "state": "CA"
        },
        "userData": {
            "phoneNetwork": "ORANGE",
            "countryCode": "BFA"
        },
        "amount": 500,
        "currency": "XOF",
        "orderId": "a7bc7cdd-8930-439a-bf53-5d2aeeb51346",
        "description": "Demo payment",
        "acsReturnUrl": "https://api.psgateway.com/AuthResult",
        "redirectSuccessUrl": "https://www.success.com",
        "redirectFailUrl": "https://www.error.com",
        "redirectCancelUrl": "https://www.cancel.com",

        "signature": "123123" # можно оставить, всё равно игнорируется
    }

    signature, string_to_sign = generate_signature(
        payload,
        PRIVATE_KEY
    )

    print(signature)