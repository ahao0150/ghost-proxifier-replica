const dgram=require('dgram'), fs=require('fs'), path=require('path');
const out=path.join(__dirname,'logs2.txt');
const s=dgram.createSocket('udp4');
s.on('message',(m)=>{ const l=m.toString('utf8'); fs.appendFileSync(out,l+'\n'); });
s.bind(45003,'127.0.0.1');
