## Опис

Ця програма дозволяє шифрувати та дешифрувати файли використовуючи алгоритм AES (Advanced Encryption Standard) за допомогою бібліотеки `pyAesCrypt`. Програма забезпечує безпечне шифрування файлів за допомогою пароля, використовуючи симетричне шифрування.

## Вимоги

Для використання цієї програми необхідно встановити наступні бібліотеки:
- `pyAesCrypt`

Встановлення можна здійснити за допомогою `pip`:
pip install pyAesCrypt

markdown
Copy code

## Використання

Програма має два основних режими: шифрування та дешифрування.

### Шифрування файлу
Щоб зашифрувати файл, введіть `1`, потім вкажіть ім'я файлу та пароль. Шифрований файл буде мати те саме ім'я, але з розширенням `.aes`.

### Дешифрування файлу
Щоб розшифрувати файл, введіть `2`, потім вкажіть ім'я файлу (з розширенням `.aes`) та пароль. Розшифрований файл буде мати оригінальне ім'я без розширення `.aes`.

## Зауваження

- Використовуйте сильні паролі для забезпечення безпеки шифрування.
- Неправильне введення пароля при дешифруванні призведе до помилки і файл не буде розшифровано.

## Ліцензія

Ця програма поширюється на умовах ліцензії MIT. Ви вільні використовувати, змінювати та розповсюджувати її в будь-яких цілях.

## Підтримка

У разі виникнення питань або проблем, будь ласка, створюйте запити на GitHub або звертайтеся до розробників.
