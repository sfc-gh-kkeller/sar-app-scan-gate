const express = require("express");
const path = require("path");
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.get("/api/data", (req, res) => res.json({ rows: [1, 2, 3] }));
global.lastResult = null;
app.listen(8080, "0.0.0.0");
