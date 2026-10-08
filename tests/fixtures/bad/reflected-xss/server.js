const express = require('express');
const app = express();
app.get('/echo', (req, res) => {
  res.send(`<div>echo: ${req.query.q}</div>`);
});
app.listen(8080);
