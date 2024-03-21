#!/usr/bin/env node
'use strict';

console.log(`==== Execute start "addSamlError.js" ====`);
require('../tools/addSamlError').execute();
console.log(`==== Execute end "addSamlError.js" ====`);

console.log(`==== Execute start "replaceSamlResponseNamespace.js" ====`);
const samlResponseNamespace = process.argv.slice(2).length === 0 ? 'samlp' : process.argv[2];
if (samlResponseNamespace !== 'samlp' && samlResponseNamespace !== 'samlp2') {
  console.log('Error Args.');
  console.log('Saml Response Namespace "' + samlResponseNamespace + '" is not string of [samlp|samlp2].');
  console.log(`==== Execute end "replaceSamlResponseNamespace.js" ====`);
  return;
}
require('../tools/replaceSamlResponseNamespace.js').execute(samlResponseNamespace);
console.log(`==== Execute end "replaceSamlResponseNamespace.js" ====`);
