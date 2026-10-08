const express = require("express");
const path = require("path");
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.get("/api/data", (req, res) => res.json({ rows: [1, 2, 3] }));
app.listen(8080, "0.0.0.0");
const SNOWFLAKE_TOKEN = 'abcd1234efgh5678ijkl';
