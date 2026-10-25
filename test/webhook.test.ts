import { createHmac } from 'node:crypto';
import { Hono } from 'hono';
import { expect, it } from 'vitest';
import { forgetSite, getSite, type AppEnv, type Env, type Site } from '../src/worker/env';
import { handleDodoWebhook } from '../src/worker/payments';

it.each([null, 'whsec_' + Buffer.from('old-secret').toString('base64')])(
  'uses the current webhook secret even when another isolate cached %s',
  async (cachedSecret) => {
    const id = `webhook-${cachedSecret ?? 'unconfigured'}`;
    const key = Buffer.from('current-secret');
    let site = { id, dodo_webhook_secret: cachedSecret } as Site;
    const statement = { bind: () => statement, first: async () => ({ ...site }) };
    const DB = { prepare: () => statement } as unknown as D1Database;
    await getSite(DB, id);
    site = { ...site, dodo_webhook_secret: 'whsec_' + key.toString('base64') };

    const app = new Hono<AppEnv>();
    app.post('/webhooks/:siteId', handleDodoWebhook);
    const body = JSON.stringify({ type: 'ignored.event', data: {} });
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const request = (signingKey: Buffer) => app.request(`/webhooks/${id}`, {
      method: 'POST',
      headers: {
        'webhook-id': 'msg_test',
        'webhook-timestamp': timestamp,
        'webhook-signature': 'v1,' + createHmac('sha256', signingKey)
          .update(`msg_test.${timestamp}.${body}`).digest('base64'),
      },
      body,
    }, { DB } as Env);

    try {
      expect((await request(key)).status).toBe(200);
      expect((await request(Buffer.from('old-secret'))).status).toBe(401);
    } finally {
      forgetSite(id);
    }
  },
);
