const http = require("http");
const fs = require("fs");
const path = require("path");
http.createServer((req, res) => {
  const f = req.url === "/" ? "index.html" : path.basename(req.url);
  fs.readFile(path.join(__dirname, "public", f), (e, b) => {
    if (e) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "content-type": f.endsWith(".js") ? "application/javascript" : "text/html" });
    res.end(b);
  });
}).listen(8080, "0.0.0.0");
