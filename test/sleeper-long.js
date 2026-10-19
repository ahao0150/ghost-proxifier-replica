const fs=require('fs'),path=require('path');
fs.writeFileSync(path.join(__dirname,'sleeper-long-pid.txt'), String(process.pid));
setTimeout(()=>process.exit(0), 300000);
