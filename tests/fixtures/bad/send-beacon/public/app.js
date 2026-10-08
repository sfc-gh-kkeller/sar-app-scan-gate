document.getElementById('b').textContent = 'hi';
navigator.sendBeacon('/track', JSON.stringify({page: 1}));
