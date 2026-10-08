const http = require("http");
http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("sar-app-scan-gate hello: published from a scanned, frozen tree\n");
}).listen(8080, "0.0.0.0");
