const fs = require('fs');
const path = require('path');

const addSamlError = () => {
  const editFile = (path, editContentFn) => {
    console.log('Replace start', path);
    let content = fs.readFileSync(path, 'utf8');
    if (!fs.existsSync(path + '.org')) {
      fs.writeFileSync(path + '.org', content, 'utf8');
      content = editContentFn(content);
      fs.writeFileSync(path, content, 'utf8');
      console.log('Replace end', path);
    } else {
      console.log('Not Replace because it has already been replaced', path);
    }
  }

  const responseTemplatePath = path.join('node_modules', 'samlp', 'templates', 'samlresponse.ejs');
  const samlpLogicPath = path.join('node_modules', 'samlp', 'lib', 'samlp.js');
  
  editFile(responseTemplatePath, (src) => {
    let edit = src;
    edit = edit.replaceAll('<samlp:StatusCode Value="<%= samlStatusCode %>"/>', '<% if (samlNestedStatusCode) { %><samlp:StatusCode Value="<%= samlStatusCode %>"><samlp:StatusCode Value="<%= samlNestedStatusCode %>"/></samlp:StatusCode><% } else { %><samlp:StatusCode Value="<%= samlStatusCode %>"/><% } %>');
    edit = edit.replaceAll('<% if (samlStatusMessage) { %><samlp:StatusMessage Value="<%= samlStatusMessage %>"/><% } %>', '<% if (samlStatusMessage) { %><samlp:StatusMessage Value="<%= samlStatusMessage %>"/><% } %><% if (samlStatusDetail) { %><samlp:StatusDetail Value="<%= samlStatusDetail %>"/><% } %>');
    return edit;
  });
  
  editFile(samlpLogicPath, (src) => {
    let edit = src;
    edit = edit.replaceAll('samlStatusCode: options.samlStatusCode,',
`
samlStatusCode: options.samlStatusCode,
samlNestedStatusCode: options.samlNestedStatusCode,
`);
    edit = edit.replaceAll('samlStatusMessage: options.samlStatusMessage,',
`
samlStatusMessage: options.samlStatusMessage,
samlStatusDetail: options.samlStatusDetail,
`);

    edit = edit.replaceAll('options.samlStatusCode = options.samlStatusCode || constants.STATUS.SUCCESS;',
`
options.samlStatusCode = options.samlStatusCode || constants.STATUS.SUCCESS;
options.samlStatusMessage = options.samlStatusMessage;
options.samlStatusDetail = options.samlStatusDetail;
`);
    edit = edit.replaceAll('options.samlStatusCode = error.code || constants.STATUS.RESPONDER;',
`
options.samlStatusCode = error.statusCode || constants.STATUS.RESPONDER;
options.samlNestedStatusCode = error.nestedStatusCode;
`);
    edit = edit.replaceAll('options.samlStatusMessage = error.description;',
`
options.samlStatusMessage = error.statusMessage;
options.samlStatusDetail = error.statusDetail;
`);
    return edit;
  });
};

const execute = () => {
  addSamlError();
};

module.exports = {
  execute,
};
