import { DurableObject } from 'cloudflare:workers';
import { Hub as HubLogic, type Env as HubEnv, type Store } from './hub';

interface Env extends HubEnv {
  HUB: DurableObjectNamespace<Hub>;
}

/** The single Durable Object that owns every vault record; requests are processed one at a time. */
export class Hub extends DurableObject<Env> {
  private logic: HubLogic;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.logic = new HubLogic(ctx.storage as unknown as Store, env);
  }

  async fetch(request: Request): Promise<Response> {
    return this.logic.handle(request);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) {
      return new Response('隨身密閱伺服器運作中。請在「打包＋管理」頁面貼上這個網址。', {
        headers: { 'content-type': 'text/plain; charset=utf-8', 'access-control-allow-origin': '*' },
      });
    }
    // Pass the caller's address to the Durable Object (it cannot see request.cf itself).
    const headers = new Headers(request.headers);
    headers.set('x-vv-ip', request.headers.get('cf-connecting-ip') ?? '');
    headers.set('x-vv-country', String((request as { cf?: { country?: string } }).cf?.country ?? ''));
    const stub = env.HUB.get(env.HUB.idFromName('hub'));
    return stub.fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;
