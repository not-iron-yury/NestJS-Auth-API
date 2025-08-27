import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';

/**
 * Здача RedisService управление IP-фильтрацией, блокировка и ограничение попыток неудачных запросов/авторизаций пользователей.
 * Реализация интерфейса OnModuleDestroy позволяет закрывать соединение с Redis при завершении модуля приложения.
 */

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private redis: Redis;
  constructor(private readonly config: ConfigService) {}

  onModuleInit() {
    this.redis = new Redis({
      host: this.config.get('REDIS_HOST', 'localhost'),
      port: Number(this.config.get('REDIS_PORT', 6379)),
      password: this.config.get('REDIS_PASSWORD') || undefined,
    });

    this.redis.on('connect', () => console.log('Redis connected'));
    this.redis.on('error', (e) => console.log('Redis error:', e));
  }

  async onModuleDestroy() {
    await this.redis.quit(); // закрывает соединение
  }

  // для теста подключения к redis
  getClient(): Redis {
    return this.redis;
  }

  // --------------------------------------------------------------- //

  // Key helpers
  ipFailKey(ip: string) {
    return `ip:fail:${ip}`; // формирует ключ для неудачных попыток входа с IP
  }
  ipBlockKey(ip: string) {
    return `ip:block:${ip}`; // формирует ключ для блокировки IP
  }

  // Увеличивает число неудачных запросов для указанного IP
  // и устанавливает время существования записи, если эта запись была создана впервые.
  async incrFail(ip: string, windowSeconds: number): Promise<number> {
    const key = this.ipFailKey(ip); // ключ для текущего ip

    const value = await this.redis.incr(key);
    // incr меняет значение ключа:
    // если ключ ранее существовал - увеличит его значение на 1
    // если ключ отсутствовал - создаст новый ключ с значением 1

    // если это первая попытка для текущего ip
    if (value === 1) {
      await this.redis.expire(key, windowSeconds); // устанавливает для ключа срок жизни
    }

    return value;
  }

  // Возвращает текущее количество неудачных попыток входа для указанного IP. Либо 0, если записи нет.
  async getFailCount(ip: string): Promise<number> {
    const count = await this.redis.get(this.ipFailKey(ip));
    return count ? Number(count) : 0;
  }

  // Удаляет для указанного IP информацию о количестве неудачных попыток
  async delFail(ip: string) {
    return this.redis.del(this.ipFailKey(ip));
  }

  // Определяет, заблокирован ли данный IP (проверят наличие ключа)
  async isIpBlocked(ip: string): Promise<boolean> {
    const exists = await this.redis.exists(this.ipBlockKey(ip)); // 1 - ключ есть, 0  - ключа нет
    return exists === 1;
  }

  // Блокирует указанный IP на заданное количество секунд (устанавливает флаг блокировки)
  async blockIp(ip: string, lockSeconds: number) {
    await this.redis.set(this.ipBlockKey(ip), '1', 'EX', lockSeconds);
  }

  // Разблокирует указанный IP (удаляет информацию по ключу блокировки)
  async unblockIp(ip: string) {
    await this.redis.del(this.ipBlockKey(ip));
  }
}
