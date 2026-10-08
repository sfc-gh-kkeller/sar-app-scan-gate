fetch('/api/data').then(r => r.json()).then(d => {
  const ul = document.getElementById('list');
  d.rows.forEach(v => { const li = document.createElement('li'); li.textContent = v; ul.appendChild(li); });
});
document.querySelector('button').addEventListener('click', () => { location.href = '/done'; });
