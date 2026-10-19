const fs=require('fs'),path=require('path');
fs.writeFileSync(path.join(__dirname,'sleeper-pid.txt'), String(process.pid));
setTimeout(()=>process.exit(0), 30000);
