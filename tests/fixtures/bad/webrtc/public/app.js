const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.example.org'}]});
const ch = pc.createDataChannel('x');
