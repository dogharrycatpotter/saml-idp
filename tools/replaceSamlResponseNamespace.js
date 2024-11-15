const fs = require('fs');
const path = require('path');

const replaceForSamlp = () => {
  const restoreFile = (path) => {
    console.log('Restore start', path);
    if (fs.existsSync(path + '.org')) {
      fs.unlinkSync(path);
      fs.renameSync(path + '.org', path);
      console.log('Restore end', path);
    } else {
      console.log('Not Restore because file does not exist', path);
    }
  }

  const assertionTemplatePath = path.join('node_modules', 'saml', 'lib', 'saml20.template');
  const responseTemplatePath = path.join('node_modules', 'samlp', 'templates', 'samlresponse.ejs');
  const logoutResponseTemplatePath = path.join('node_modules', 'samlp', 'templates', 'logoutresponse.ejs');
  const saml20LogicPath = path.join('node_modules', 'saml', 'lib', 'saml20.js');

  restoreFile(assertionTemplatePath);
  restoreFile(responseTemplatePath);
  restoreFile(logoutResponseTemplatePath);
  restoreFile(saml20LogicPath);
};

const replaceForSamlp2 = () => {
  const editFile = (path, editContentFn, isForce) => {
    console.log('Replace start', path);
    let content = fs.readFileSync(path, 'utf8');
    if (!fs.existsSync(path + '.org') || isForce) {
      fs.writeFileSync(path + '.org', content, 'utf8');
      content = editContentFn(content);
      fs.writeFileSync(path, content, 'utf8');
      console.log('Replace end', path);
    } else {
      console.log('Not Replace because it has already been replaced', path);
    }
  }
  
  const editTemplateForSamlNamespace = (src) => {
    let edit = src;
    edit = edit.replaceAll('<samlp:', '<samlp2:');
    edit = edit.replaceAll('</samlp:', '</samlp2:');
    edit = edit.replaceAll('<saml:', '<saml2:');
    edit = edit.replaceAll('</saml:', '</saml2:');
    edit = edit.replaceAll('xmlns:samlp=', 'xmlns:samlp2=');
    edit = edit.replaceAll('xmlns:saml=', 'xmlns:saml2=');
    return edit;
  }
  
  const assertionTemplatePath = path.join('node_modules', 'saml', 'lib', 'saml20.template');
  const responseTemplatePath = path.join('node_modules', 'samlp', 'templates', 'samlresponse.ejs');
  const logoutResponseTemplatePath = path.join('node_modules', 'samlp', 'templates', 'logoutresponse.ejs');
  const saml20LogicPath = path.join('node_modules', 'saml', 'lib', 'saml20.js');
  
  editFile(assertionTemplatePath, editTemplateForSamlNamespace);
  editFile(responseTemplatePath, editTemplateForSamlNamespace, true);
  editFile(logoutResponseTemplatePath, editTemplateForSamlNamespace, true);
  editFile(saml20LogicPath, (src) => {
    let edit = src;
    edit = edit.replaceAll('saml:', 'saml2:');
    edit = edit.replaceAll("'NotBefore', now.format", "'NotBefore', now.clone().add(-1 * 60, 'seconds').format");
    return edit;
  });
};

const execute = (type) => {
  if (type === 'samlp2') {
    replaceForSamlp2();
  } else {
    replaceForSamlp();
  }
};

module.exports = {
  execute,
};
