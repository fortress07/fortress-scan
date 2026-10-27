import Router from 'koa-router';
import { exec } from 'child_process';
import { Sequelize, QueryTypes } from 'sequelize';

const sequelize = new Sequelize('sqlite::memory:');
const router = new Router();

router.get('/orders', async (ctx) => {
  const status: string = ctx.query.status as string;
  ctx.body = await sequelize.query(`SELECT * FROM orders WHERE status = '${status}'`, { type: QueryTypes.SELECT }); // fsb-expect: FSB-SQL-001
});

router.get('/orders-safe', async (ctx) => {
  ctx.body = await sequelize.query('SELECT * FROM orders WHERE status = :status', {
    replacements: { status: ctx.query.status },
    type: QueryTypes.SELECT,
  });
});

router.post('/convert', async (ctx) => {
  const { file } = ctx.request.body as { file: string };
  exec(`convert ${file} out.png`); // fsb-expect: FSB-CMD-001
  ctx.status = 202;
});

router.get('/limit', async (ctx) => {
  const limit = Number(ctx.query.limit);
  ctx.body = await sequelize.query('SELECT * FROM orders LIMIT ' + limit, { type: QueryTypes.SELECT });
});

export default router;
