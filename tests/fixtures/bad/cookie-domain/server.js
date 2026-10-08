const express = require("express");
const path = require("path");
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.get("/login", (req, res) => { res.setHeader("Set-Cookie", "sid=abc; Path=/; Domain=.snowflakecomputing.app; Secure"); res.end("ok"); });
app.get("/api/data", (req, res) => res.json({ rows: [1, 2, 3] }));
app.listen(8080, "0.0.0.0");
