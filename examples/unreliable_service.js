/**
 * Example JavaScript service with reliability risks for scanner demos.
 */

const express = require('express');
const axios = require('axios');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.post('/orders', async (req, res) => {
  const payment = await axios.post('https://payments.example/charge', req.body);
  res.json(payment.data);
});

setInterval(async () => {
  try {
    await publishNextJob();
  } catch (err) {}
}, 1000);

module.exports = app;
