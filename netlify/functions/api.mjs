import { getStore } from '@netlify/blobs';
import { createApi } from '../lib/core.mjs';

const handle = createApi({
  getStore: () => getStore({ name: 'ilc-painel-fretes', consistency: 'strong' }),
  env: {
    ILC_ADMIN_EMAIL: process.env.ILC_ADMIN_EMAIL,
    ILC_ADMIN_NAME: process.env.ILC_ADMIN_NAME,
    ILC_ADMIN_PASSWORD: process.env.ILC_ADMIN_PASSWORD,
    SESSION_SECRET: process.env.SESSION_SECRET,
  },
});

export default async (req) => handle(req);

export const config = { path: '/api/*' };
