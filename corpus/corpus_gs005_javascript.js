// SQLi test corpus for GS005 — JavaScript/TypeScript patterns.
// Every uncommented line should be detected.

// ═══ POSITIVE — Node.js template literal ═══════════════════════════════
await pool.query(`SELECT * FROM users WHERE name = '${req.body.name}'`)
await db.execute(`INSERT INTO audit (user, action) VALUES ('${user}', '${action}')`)

// ═══ POSITIVE — Sequelize ═════════════════════════════════════════════
await sequelize.query(`SELECT id FROM products WHERE sku = '${sku}'`)
await sequelize.query("SELECT * FROM logs WHERE user_id = " + userId)

// ═══ POSITIVE — Knex ═════════════════════════════════════════════════
await knex.raw(`SELECT * FROM logs WHERE user_id = ${userId}`)
await knex.raw("SELECT * FROM sessions WHERE token = '" + token + "'")

// ═══ POSITIVE — String concat ═════════════════════════════════════════
pool.query("SELECT * FROM users WHERE email = '" + email + "' AND active = 1")

// ═══ POSITIVE — MongoDB NoSQL Injection ═══════════════════════════════
db.collection.find({ $where: `this.name == '${req.query.name}'` })
db.collection.find({ name: { $regex: req.params.search } })  // $regex from user input
