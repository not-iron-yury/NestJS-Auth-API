import { createHmac, randomBytes } from 'crypto';

// Вычисляет HMAC (Hash-based Message Authentication Code) с использованием алгоритма SHA-256
// и возвращает результат в виде шестнадцатеричной строки (hex).
export function HmacSha256Hex(value: string): string {
  return createHmac('sha256', process.env.HMAC_SECRET || 'default_secret') // создает объект HMAC с алгоритмом шифрования "sha256" и указанным секретным ключом (secret)
    .update(value) // применяет обновление хэша к указанному значению (value) для вычисления итогового хэша
    .digest('hex'); // возвращает финальный результат в виде шестнадцатеричного представления ("hex")
}

// Генерация шестизначного числового кода
export function generateSms() {
  const buffer = randomBytes(3);
  let num = buffer.readUIntBE(0, 3);
  num %= 1000000;
  return String(num).padStart(6, '0');
}
