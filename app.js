
/**
 * Module dependencies.
 */

const chalk               = require('chalk'),
      express             = require('express'),
      os                  = require('os'),
      fs                  = require('fs'),
      http                = require('http'),
      https               = require('https'),
      path                = require('path'),
      extend              = require('extend'),
      hbs                 = require('hbs'),
      logger              = require('morgan'),
      bodyParser          = require('body-parser'),
      session             = require('express-session'),
      yargs               = require('yargs/yargs'),
      xmlFormat           = require('xml-formatter'),
      samlp               = require('samlp'),
      Parser              = require('@xmldom/xmldom').DOMParser,
      SessionParticipants = require('samlp/lib/sessionParticipants'),
      SimpleProfileMapper = require('./lib/simpleProfileMapper.js');

const jwt = require("jsonwebtoken");

/**
 * Globals
 */

const IDP_PATHS = {
  SSO: '/saml/sso',
  SLO: '/saml/slo',
  METADATA: '/metadata',
  SIGN_IN: '/signin',
  SIGN_OUT: '/signout',
  SETTINGS: '/settings',
  SET_SAVED_USER: '/setuser',
  UPDATE_USER: '/updateuser',
  GET_USER: '/getuser',
  CLEAR_USER: '/clearuser',
  CREATE_TOKEN: '/createtoken',
  VERIFY_TOKEN: '/verifytoken'
}
const CERT_OPTIONS = [
  'cert',
  'key',
  'encryptionCert',
  'encryptionPublicKey',
  'httpsPrivateKey',
  'httpsCert',
];
const WILDCARD_ADDRESSES = ['0.0.0.0', '::'];
const UNDEFINED_VALUE = 'None';
const CRYPT_TYPES = {
  certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
  'RSA private key': /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
  'public key': /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
};
const KEY_CERT_HELP_TEXT = dedent(chalk`
  To generate a key/cert pair for the IdP, run the following command:

  {gray openssl req -x509 -new -newkey rsa:2048 -nodes \
    -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' \
    -keyout idp-private-key.pem \
    -out idp-public-cert.pem -days 7300}`
);

function matchesCertType(value, type) {
  return CRYPT_TYPES[type] && CRYPT_TYPES[type].test(value);
}

function resolveFilePath(filePath) {

  if (filePath.startsWith('saml-idp/')) {
    // Allows file path options to files included in this package, like config.js
    const resolvedPath = require.resolve(filePath.replace(/^saml\-idp\//, `${__dirname}/`));
    return fs.existsSync(resolvedPath) && resolvedPath;
  }
  var possiblePath;
  if (fs.existsSync(filePath)) {
    return filePath;
  }
  if (filePath.startsWith('~/')) {
    possiblePath = path.resolve(process.env.HOME, filePath.slice(2));
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    } else {
      // for ~/ paths, don't try to resolve further
      return filePath;
    }
  }
  return ['.', __dirname]
    .map(base => path.resolve(base, filePath))
    .find(possiblePath => fs.existsSync(possiblePath));
}

function makeCertFileCoercer(type, description, helpText) {
  return function certFileCoercer(value) {
    if (matchesCertType(value, type)) {
      return value;
    }

    const filePath = resolveFilePath(value);
    if (filePath) {
      return fs.readFileSync(filePath)
    }
    throw new Error(
      chalk`{red Invalid / missing {bold ${description}}} - {yellow not a valid crypt key/cert or file path}${helpText ? '\n' + helpText : ''}`
    )
  };
}

function getHashCode(str) {
  var hash = 0;
  if (str.length == 0) return hash;
  for (i = 0; i < str.length; i++) {
    char = str.charCodeAt(i);
    hash = ((hash<<5)-hash)+char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash;
}

function dedent(str) {
  // Reduce the indentation of all lines by the indentation of the first line
  const match = str.match(/^\n?( +)/);
  if (!match) {
    return str;
  }
  const indentRe = new RegExp(`\n${match[1]}`, 'g');
  return str.replace(indentRe, '\n').replace(/^\n/, '');
}

function formatOptionValue(key, value) {
  if (typeof value === 'string') {
    return value;
  }
  if (CERT_OPTIONS.includes(key)) {
    return chalk`${
      value.toString()
        .replace(/-----.+?-----|\n/g, '')
        .substring(0, 80)
    }{white …}`;
  }
  if (!value && value !== false) {
    return UNDEFINED_VALUE;
  }
  if (typeof value === 'function') {
    const lines = `${value}`.split('\n');
    return lines[0].slice(0, -2);
  }
  return `${JSON.stringify(value)}`;
}

function prettyPrintXml(xml, indent) {
  // This works well, because we format the xml before applying the replacements
  const prettyXml = xmlFormat(xml, {indentation: '  '})
    // Matches `<{prefix}:{name} .*?>`
    .replace(/<(\/)?((?:[\w]+)(?::))?([\w]+)(.*?)>/g, chalk`<{green $1$2{bold $3}}$4>`)
    // Matches ` {attribute}="{value}"
    .replace(/ ([\w:]+)="(.+?)"/g, chalk` {white $1}={cyan "$2"}`);
  if (indent) {
    return prettyXml.replace(/(^|\n)/g, `$1${' '.repeat(indent)}`);
  }
  return prettyXml;
}


/**
 * Arguments
 */
function processArgs(args, options) {
  var baseArgv;

  if (options) {
    baseArgv = yargs(args).config(options);
  } else {
    baseArgv = yargs(args);
  }
  return baseArgv
    .usage('\nSimple IdP for SAML 2.0 WebSSO & SLO Profile\n\n' +
        'Launches an IdP web server that mints SAML assertions or logout responses for a Service Provider (SP)\n\n' +
        'Usage:\n\t$0 --acsUrl {url} --audience {uri}')
    .alias({h: 'help'})
    .options({
      host: {
        description: 'IdP Web Server Listener Host',
        required: false,
        default: 'localhost'
      },
      port: {
        description: 'IdP Web Server Listener Port',
        required: true,
        alias: 'p',
        default: 7000
      },
      cert: {
        description: 'IdP Signature PublicKey Certificate',
        required: true,
        default: './idp-public-cert.pem',
        coerce: makeCertFileCoercer('certificate', 'IdP Signature PublicKey Certificate', KEY_CERT_HELP_TEXT)
      },
      dataDir: {
        description: 'Data Directory',
        required: true
      },
      key: {
        description: 'IdP Signature PrivateKey Certificate',
        required: true,
        default: './idp-private-key.pem',
        coerce: makeCertFileCoercer('RSA private key', 'IdP Signature PrivateKey Certificate', KEY_CERT_HELP_TEXT)
      },
      issuer: {
        description: 'IdP Issuer URI',
        required: true,
        alias: 'iss',
        default: 'urn:example:idp'
      },
      acsUrl: {
        description: 'SP Assertion Consumer URL',
        required: true,
        alias: 'acs'
      },
      sloUrl: {
        description: 'SP Single Logout URL',
        required: false,
        alias: 'slo'
      },
      audience: {
        description: 'SP Audience URI',
        required: true,
        alias: 'aud'
      },
      serviceProviderId: {
        description: 'SP Issuer/Entity URI',
        required: false,
        alias: 'spId',
        string: true
      },
      relayState: {
        description: 'Default SAML RelayState for SAMLResponse',
        required: false,
        alias: 'rs'
      },
      disableRequestAcsUrl: {
        description: 'Disables ability for SP AuthnRequest to specify Assertion Consumer URL',
        required: false,
        boolean: true,
        alias: 'static',
        default: false
      },
      encryptAssertion: {
        description: 'Encrypts assertion with SP Public Key',
        required: false,
        boolean: true,
        alias: 'enc',
        default: false
      },
      encryptionCert: {
        description: 'SP Certificate (pem) for Assertion Encryption',
        required: false,
        string: true,
        alias: 'encCert',
        coerce: makeCertFileCoercer('certificate', 'Encryption cert')
      },
      encryptionPublicKey: {
        description: 'SP RSA Public Key (pem) for Assertion Encryption ' +
        '(e.g. openssl x509 -pubkey -noout -in sp-cert.pem)',
        required: false,
        string: true,
        alias: 'encKey',
        coerce: makeCertFileCoercer('public key', 'Encryption public key')
      },
      httpsPrivateKey: {
        description: 'Web Server TLS/SSL Private Key (pem)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('RSA private key')
      },
      httpsCert: {
        description: 'Web Server TLS/SSL Certificate (pem)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('certificate')
      },
      https: {
        description: 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)',
        required: true,
        boolean: true,
        default: false
      },
      signResponse: {
        description: 'Enables signing of responses',
        required: false,
        boolean: true,
        default: true,
        alias: 'signResponse'
      },
      configFile: {
        description: 'Path to a SAML attribute config file',
        required: true,
        default: 'saml-idp/config.js',
        alias: 'conf'
      },
      rollSession: {
        description: 'Create a new session for every authn request instead of reusing an existing session',
        required: false,
        boolean: true,
        default: false
      },
      authnContextClassRef: {
        description: 'Authentication Context Class Reference',
        required: false,
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        alias: 'acr'
      },
      authnContextDecl: {
        description: 'Authentication Context Declaration (XML FilePath)',
        required: false,
        string: true,
        alias: 'acd',
        coerce: function (value) {
          const filePath = resolveFilePath(value);
          if (filePath) {
            return fs.readFileSync(filePath, 'utf8')
          }
        }
      },
      lifetimeInSeconds: {
        description: 'NotOnOrAfter Seconds',
        required: false,
        default: 60 * 60, // 1時間
      },
      isEnableToken: {
        description: 'Token Enable Flag',
        required: false,
        default: false,
      },
      tokenExpires: {
        description: 'Token Expires Seconds',
        required: false,
        default: 60 * 60, // 1時間
      }
    })
    .example('$0 --acsUrl http://acme.okta.com/auth/saml20/exampleidp --audience https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV', '')
    .check(function(argv, aliases) {
      if (argv.encryptAssertion) {
        if (argv.encryptionPublicKey === undefined) {
          return 'encryptionPublicKey argument is also required for assertion encryption';
        }
        if (argv.encryptionCert === undefined) {
          return 'encryptionCert argument is also required for assertion encryption';
        }
      }
      return true;
    })
    .check(function(argv, aliases) {
      if (argv.config) {
        return true;
      }
      const configFilePath = resolveFilePath(argv.configFile);

      if (!configFilePath) {
        return 'SAML attribute config file path "' + argv.configFile + '" is not a valid path.\n';
      }
      try {
        argv.config = require(configFilePath);
      } catch (error) {
        return 'Encountered an exception while loading SAML attribute config file "' + configFilePath + '".\n' + error;
      }
      return true;
    })
    .check(function(argv, aliases) {
      const dataDir = resolveDataDir(argv.dataDir, '');
      if (!fs.existsSync(dataDir)) {
        return 'Data Directory "' + resolveDataDir(argv.dataDir, '') + '" is not exist.\n'
      }
      return true;
    })
    .check(function(argv, aliases) {
      if (!Number.isInteger(argv.lifetimeInSeconds)) {
        return 'NotOnOrAfter Seconds "' + argv.lifetimeInSeconds + '" is not integer.\n';
      }
      argv.lifetimeInSeconds = Number(argv.lifetimeInSeconds);
      if (argv.isEnableToken !== 'true' && argv.isEnableToken !== 'false') {
        return 'Token Enable Flag "' + argv.isEnableToken + '" is not string of boolean[true|false].\n';
      }
      argv.isEnableToken = argv.isEnableToken === 'true' ? true : false;
      if (!Number.isInteger(argv.tokenExpires)) {
        return 'Token Expires Seconds "' + argv.tokenExpires + '" is not integer.\n';
      }
      argv.tokenExpires = Number(argv.tokenExpires);
      return true;
    })
    .wrap(baseArgv.terminalWidth());
}

function _runServer(argv) {
  const app = express();
  const httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);
  const blocks = {};

  console.log(dedent(chalk`
    Listener Port:
      {cyan ${argv.host}:${argv.port}}
    HTTPS Enabled:
      {cyan ${argv.https}}

    {bold [{yellow Identity Provider}]}

    Issuer URI:
      {cyan ${argv.issuer}}
    Sign Response Message:
      {cyan ${argv.signResponse}}
    Encrypt Assertion:
      {cyan ${argv.encryptAssertion}}
    Authentication Context Class Reference:
      {cyan ${argv.authnContextClassRef || UNDEFINED_VALUE}}
    Authentication Context Declaration:
      {cyan ${argv.authnContextDecl || UNDEFINED_VALUE}}
    Default RelayState:
      {cyan ${argv.relayState || UNDEFINED_VALUE}}

    {bold [{yellow Service Provider}]}

    Issuer URI:
      {cyan ${argv.serviceProviderId || UNDEFINED_VALUE}}
    Audience URI:
      {cyan ${argv.audience || UNDEFINED_VALUE}}
    ACS URL:
      {cyan ${argv.acsUrl || UNDEFINED_VALUE}}
    SLO URL:
      {cyan ${argv.sloUrl || UNDEFINED_VALUE}}
    Trust ACS URL in Request:
      {cyan ${!argv.disableRequestAcsUrl}}
  `));


  /**
   * IdP Configuration
   */

  const idpOptions = {
    issuer:                 argv.issuer,
    serviceProviderId:      argv.serviceProviderId || argv.audience,
    cert:                   argv.cert,
    key:                    argv.key,
    audience:               argv.audience,
    recipient:              argv.acsUrl,
    destination:            argv.acsUrl,
    acsUrl:                 argv.acsUrl,
    sloUrl:                 argv.sloUrl,
    RelayState:             argv.relayState,
    allowRequestAcsUrl:     !argv.disableRequestAcsUrl,
    digestAlgorithm:        'sha256',
    signatureAlgorithm:     'rsa-sha256',
    signResponse:           argv.signResponse,
    encryptAssertion:       argv.encryptAssertion,
    encryptionCert:         argv.encryptionCert,
    encryptionPublicKey:    argv.encryptionPublicKey,
    encryptionAlgorithm:    'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    lifetimeInSeconds:      argv.lifetimeInSeconds,
    authnContextClassRef:   argv.authnContextClassRef,
    authnContextDecl:       argv.authnContextDecl,
    includeAttributeNameFormat: true,
    profileMapper:          SimpleProfileMapper.fromMetadata(argv.config.metadata),
    postEndpointPath:       IDP_PATHS.SSO,
    redirectEndpointPath:   IDP_PATHS.SSO,
    logoutEndpointPaths:    argv.sloUrl ?
                            {
                              redirect: IDP_PATHS.SLO,
                              post: IDP_PATHS.SLO
                            } : {},
    getUserFromRequest:     function(req) { return req.user; },
    getPostURL:             function (audience, authnRequestDom, req, callback) {
                              return callback(null, (req.authnRequest && req.authnRequest.acsUrl) ?
                                req.authnRequest.acsUrl :
                                req.idp.options.acsUrl);
                            },
    transformAssertion:     function(assertionDom) {
                              if (argv.authnContextDecl) {
                                var declDoc;
                                try {
                                  declDoc = new Parser().parseFromString(argv.authnContextDecl);
                                } catch(err){
                                  console.log('Unable to parse Authentication Context Declaration XML', err);
                                }
                                if (declDoc) {
                                  const authnContextDeclEl = assertionDom.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDecl');
                                  authnContextDeclEl.appendChild(declDoc.documentElement);
                                  const authnContextEl = assertionDom.getElementsByTagName('saml:AuthnContext')[0];
                                  authnContextEl.appendChild(authnContextDeclEl);
                                }
                              }
                            },
    responseHandler:        function(response, opts, req, res, next) {
                              console.log(dedent(chalk`
                                Sending SAML Response to {cyan ${opts.postUrl}} =>
                                  {bold RelayState} =>
                                    {cyan ${opts.RelayState || UNDEFINED_VALUE}}
                                  {bold SAMLResponse} =>`
                              ));

                              console.log(prettyPrintXml(response.toString(), 4));

                              res.render('samlresponse', {
                                AcsUrl: opts.postUrl,
                                SAMLResponse: response.toString('base64'),
                                RelayState: opts.RelayState
                              });
                            }
  }

  /**
   * App Environment
   */

  app.set('host', process.env.HOST || argv.host);
  app.set('port', process.env.PORT || argv.port);
  app.set('views', path.join(__dirname, 'views'));

  /**
   * View Engine
   */

  app.set('view engine', 'hbs');
  app.set('view options', { layout: 'layout' })
  app.engine('handlebars', hbs.__express);

  // Register Helpers
  hbs.registerHelper('extend', function(name, context) {
    var block = blocks[name];
    if (!block) {
      block = blocks[name] = [];
    }

    block.push(context.fn(this));
  });

  hbs.registerHelper('block', function(name) {
    const val = (blocks[name] || []).join('\n');
    // clear the block
    blocks[name] = [];
    return val;
  });


  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value=\"' + selected + '\"'), '$& selected="selected"');
  });

  hbs.registerHelper('getProperty', function(attribute, context) {
    return context[attribute];
  });

  hbs.registerHelper('serialize', function(context) {
    return new Buffer(JSON.stringify(context)).toString('base64');
  });

  /**
   * Middleware
   */

  app.use(logger(':date> :method :url - {:referrer} => :status (:response-time ms)', {
    skip: function (req, res)
      {
        return req.path.startsWith('/bower_components') || req.path.startsWith('/css')
      }
  }));
  app.use(express.json());
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    secret: 'The universe works on a math equation that never even ever really ends in the end',
    resave: false,
    saveUninitialized: true,
    name: 'idp_sid',
    cookie: { maxAge: 60 * 60 * 1000 }
  }));

  /**
   * View Handlers
   */

  const showUser = function (req, res, next) {
    res.render('user', {
      user: req.user,
      participant: req.participant,
      metadata: req.metadata,
      authnRequest: req.authnRequest,
      idp: req.idp.options,
      paths: IDP_PATHS
    });
  }

  /**
   * Shared Handlers
   */

  const parseSamlRequest = function(req, res, next) {
    samlp.parseRequest(req, function(err, data) {
      if (err) {
        return res.render('error', {
          message: 'SAML AuthnRequest Parse Error: ' + err.message,
          error: err
        });
      };
      if (data) {
        req.authnRequest = {
          relayState: req.query.RelayState || req.body.RelayState,
          id: data.id,
          issuer: data.issuer,
          destination: data.destination,
          acsUrl: data.assertionConsumerServiceURL,
          forceAuthn: data.forceAuthn === 'true'
        };
        console.log('Received AuthnRequest => \n', req.authnRequest);
      }

      // Set saved user
      const savedUser = getSavedUser(argv.dataDir, req.user);
      if (savedUser) {
        console.log(`Set saved user`);
        req.user = savedUser;
      }

      return showUser(req, res, next);
    })
  };

  const verifyAccessToken = async function(req, res, next) {
    if (argv.isEnableToken) {
      const authHeader = req.headers["authorization"];
      if (authHeader) {
        if (authHeader.split(" ")[0] === "Bearer") {
          const token = authHeader.split(" ")[1];
          try {
            const decodedToken = await verifyToken(argv.key, token);
            res.locals.decodedToken = decodedToken;
            next();
          } catch (err) {
            res.status(401).end();
          }
        } else {
          res.status(401).end();
        }
      } else {
        res.status(401).end();
      }  
    } else {
      res.locals.decodedToken = 'none';
      next();
    }
  };

  const getSessionIndex = function(req) {
    if (req && req.session) {
      return Math.abs(getHashCode(req.session.id)).toString();
    }
  }

  const getParticipant = function(req) {
    return {
      serviceProviderId: req.idp.options.serviceProviderId,
      sessionIndex: getSessionIndex(req),
      nameId: req.user.userName,
      nameIdFormat: req.user.nameIdFormat,
      serviceProviderLogoutURL: req.idp.options.sloUrl
    }
  }

  const parseLogoutRequest = function(req, res, next) {
    if (!req.idp.options.sloUrl) {
      return res.render('error', {
        message: 'SAML Single Logout Service URL not defined for Service Provider'
      });
    };

    console.log('Processing SAML SLO request for participant => \n', req.participant);

    return samlp.logout({
      issuer:                 req.idp.options.issuer,
      cert:                   req.idp.options.cert,
      key:                    req.idp.options.key,
      digestAlgorithm:        req.idp.options.digestAlgorithm,
      signatureAlgorithm:     req.idp.options.signatureAlgorithm,
      sessionParticipants:    new SessionParticipants(
      [
        req.participant
      ]),
      clearIdPSession: function(callback) {
        console.log('Destroying session ' + req.session.id + ' for participant', req.participant);
        req.session.destroy();
        callback();
      }
    })(req, res, next);
  }

  /**
   * Routes
   */

  app.use(function(req, res, next){
    if (argv.rollSession) {
      req.session.regenerate(function(err) {
        return next();
      });
    } else {
      next()
    }
  });

  app.use(function(req, res, next){
    req.user = argv.config.user;
    req.metadata = argv.config.metadata;
    req.idp = { options: idpOptions };
    req.participant = getParticipant(req);
    next();
  });

  app.get(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);
  app.post(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);

  app.get(IDP_PATHS.SLO, parseLogoutRequest);
  app.post(IDP_PATHS.SLO, parseLogoutRequest);

  app.post(IDP_PATHS.SIGN_IN, function(req, res) {
    const authOptions = extend({}, req.idp.options);
    Object.keys(req.body).forEach(function(key) {
      var buffer;
      if (key === '_authnRequest') {
        buffer = new Buffer(req.body[key], 'base64');
        req.authnRequest = JSON.parse(buffer.toString('utf8'));

        // Apply AuthnRequest Params
        authOptions.inResponseTo = req.authnRequest.id;
        if (req.idp.options.allowRequestAcsUrl && req.authnRequest.acsUrl) {
          authOptions.acsUrl = req.authnRequest.acsUrl;
          authOptions.recipient = req.authnRequest.acsUrl;
          authOptions.destination = req.authnRequest.acsUrl;
          authOptions.forceAuthn = req.authnRequest.forceAuthn;
        }
        if (req.authnRequest.relayState) {
          authOptions.RelayState = req.authnRequest.relayState;
        }
      } else {
        const excludes = ['statusCode', 'nestedStatusCode', 'statusMessage', 'statusDetail'];
        if (!excludes.includes(key)) {
          req.user[key] = req.body[key];
        }
      }
    });

    // Save user
    // req.user.loginDate = new Date();
    if (req.body.statusCode === 'Success') {
      saveUser(argv.dataDir, req.user);
    }

    if (!authOptions.encryptAssertion) {
      delete authOptions.encryptionCert;
      delete authOptions.encryptionPublicKey;
    }

    // Set Session Index
    authOptions.sessionIndex = getSessionIndex(req);

    // Keep calm and Single Sign On
    console.log(dedent(chalk`
      Generating SAML Response using =>
        {bold User} => ${Object.entries(req.user).map(([key, value]) => chalk`
          ${key}: {cyan ${value}}`
        ).join('')}
        {bold SAMLP Options} => ${Object.entries(authOptions).map(([key, value]) => chalk`
          ${key}: {cyan ${formatOptionValue(key, value)}}`
        ).join('')}
    `));
    if (req.body.statusCode === 'Success') {
      if (req.body.statusMessage) {
        authOptions.samlStatusMessage = req.body.statusMessage;
      }
      if (req.body.statusDetail) {
        authOptions.samlStatusDetail = req.body.statusDetail;
      }
      samlp.auth(authOptions)(req, res);
    } else {
      authOptions.error = {
        statusCode: `urn:oasis:names:tc:SAML:2.0:status:${req.body.statusCode}`,
        ...(req.body.nestedStatusCode ? { nestedStatusCode: req.body.nestedStatusCode } : {}),
        ...(req.body.statusMessage ? { statusMessage: req.body.statusMessage } : {}),
        ...(req.body.statusDetail ? { statusDetail: req.body.statusDetail } : {}),
      };
      authOptions.getPostURL = function (req, callback) {
        callback(null, req.idp.options.acsUrl);
      };
      samlp.sendError(authOptions)(req, res);  
    }
  })

  app.get(IDP_PATHS.METADATA, function(req, res, next) {
    samlp.metadata(req.idp.options)(req, res);
  });

  app.post(IDP_PATHS.METADATA, function(req, res, next) {
    if (req.body && req.body.attributeName && req.body.displayName) {
      var attributeExists = false;
      const attribute = {
        id: req.body.attributeName,
        optional: true,
        displayName: req.body.displayName,
        description: req.body.description || '',
        multiValue: req.body.valueType === 'multi'
      };

      req.metadata.forEach(function(entry) {
        if (entry.id === req.body.attributeName) {
          entry = attribute;
          attributeExists = true;
        }
      });

      if (!attributeExists) {
        req.metadata.push(attribute);
      }
      console.log("Updated SAML Attribute Metadata => \n", req.metadata)
      res.status(200).end();
    }
  });

  app.get(IDP_PATHS.SIGN_OUT, function(req, res, next) {
    if (req.idp.options.sloUrl) {
      console.log('Initiating SAML SLO request for user: ' + req.user.userName +
      ' with sessionIndex: ' + getSessionIndex(req));
      res.redirect(IDP_PATHS.SLO);
    } else {
      console.log('SAML SLO is not enabled for SP, destroying IDP session');
      req.session.destroy(function(err) {
        if (err) {
          throw err;
        }
        res.redirect('back');
      })
    }
  });

  app.get([IDP_PATHS.SETTINGS], function(req, res, next) {
    res.render('settings', {
      idp: req.idp.options
    });
  });

  app.post([IDP_PATHS.SETTINGS], function(req, res, next) {
    Object.keys(req.body).forEach(function(key) {
      switch(req.body[key].toLowerCase()){
        case "true": case "yes": case "1":
          req.idp.options[key] = true;
          break;
        case "false": case "no": case "0":
          req.idp.options[key] = false;
          break;
        default:
          req.idp.options[key] = req.body[key];
          break;
      }

      if (req.body[key].match(/^\d+$/)) {
        req.idp.options[key] = parseInt(req.body[key], '10');
      }
    });

    console.log('Updated IdP Configuration => \n', req.idp.options);
    res.redirect('/');
  });

  app.post(IDP_PATHS.SET_SAVED_USER, function(req, res, next) {
    if (req.body && req.body.userName) {
      const savedUser = getSavedUser(argv.dataDir, { userName: req.body.userName });
      if (savedUser) {
        console.log('Set saved user');
        req.user = savedUser;
        res.status(200).end();
      } else {
        res.status(404).end();
      }
    } else {
      res.status(404).end();
    }
  });

  app.post(IDP_PATHS.UPDATE_USER, verifyAccessToken, function(req, res, next) {
    console.log('/updateuser', req.body);
    if (req.body && req.body.userName && (req.body.appUserId1 || req.body.appUserId2)) {
      const savedUser = getSavedUser(argv.dataDir, { userName: req.body.userName });
      if (savedUser) {
        if (req.body.appUserId1) {
          savedUser.appUserId1 = req.body.appUserId1;
        }
        if (req.body.appUserId2) {
          savedUser.appUserId2 = req.body.appUserId2;
        }
        saveUser(argv.dataDir, savedUser);
        console.log('Update user');
        res.status(200).json({ success: true });
      } else {
        res.status(404).end();
      }
    } else {
      res.status(404).end();
    }
  });

  app.get(IDP_PATHS.GET_USER, verifyAccessToken, function(req, res, next) {
    console.log('/getuser', req.query);
    if (req.query) {
      if (req.query.userName) {
        const savedUser = getSavedUser(argv.dataDir, { userName: req.query.userName });
        if (savedUser) {
          console.log('Get user');
          res.status(200).json(savedUser);
        } else {
          res.status(404).end();
        }
      } else if (req.query.appUserId1) {
        const savedUser = getSavedUserOfAppUserId1(argv.dataDir, req.query.appUserId1);
        if (savedUser) {
          console.log('Get user');
          res.status(200).json(savedUser);
        } else {
          res.status(404).end();
        }
      } else if (req.query.appUserId2) {
        const savedUser = getSavedUserOfAppUserId2(argv.dataDir, req.query.appUserId2);
        if (savedUser) {
          console.log('Get user');
          res.status(200).json(savedUser);
        } else {
          res.status(404).end();
        }
      } else {
        res.status(404).end();
      }
    } else {
      res.status(404).end();
    }
  });

  app.get(IDP_PATHS.CLEAR_USER, verifyAccessToken, function(req, res, next) {
    console.log('/clearuser');
    clearSaveUser(argv.dataDir);
    res.status(200).json({ success: true });
  });

  app.get([IDP_PATHS.CREATE_TOKEN], function(req, res, next) {
    console.log('/createtoken expires', argv.tokenExpires);
    const token = createToken(argv.key, argv.tokenExpires);
    res.status(200).json({ token });
  });

  app.post([IDP_PATHS.VERIFY_TOKEN], verifyAccessToken, function(req, res, next) {
    console.log('/verifytoken');
    res.status(200).json({ token: res.locals.decodedToken });
  });

  // catch 404 and forward to error handler
  app.use(function(req, res, next) {
    const err = new Error('Route Not Found');
    err.status = 404;
    next(err);
  });

  // development error handler
  app.use(function(err, req, res, next) {
    if (err) {
      res.status(err.status || 500);
      res.render('error', {
          message: err.message,
          error: err
      });
    }
  });

  /**
   * Start IdP Web Server
   */

  console.log(chalk`Starting IdP server on port {cyan ${app.get('host')}:${app.get('port')}}...\n`);

  httpServer.listen(app.get('port'), app.get('host'), function() {
    const scheme          = argv.https ? 'https' : 'http',
          {address, port} = httpServer.address(),
          hostname        = WILDCARD_ADDRESSES.includes(address) ? os.hostname() : 'localhost',
          baseUrl         = `${scheme}://${hostname}:${port}`;

    console.log(dedent(chalk`
      IdP Metadata URL:
        {cyan ${baseUrl}${IDP_PATHS.METADATA}}

      SSO Bindings:
        urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
          => {cyan ${baseUrl}${IDP_PATHS.SSO}}
        urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
          => {cyan ${baseUrl}${IDP_PATHS.SSO}}
      ${argv.sloUrl ? `
      SLO Bindings:
        urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
          => {cyan ${baseUrl}${IDP_PATHS.SLO}}
        urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
          => {cyan ${baseUrl}${IDP_PATHS.SLO}}
      ` : ''}
      IdP server ready at
        {cyan ${baseUrl}}
    `));
  });
  return httpServer;
}

function runServer(options) {
  const args = processArgs([], options);
  return _runServer(args.argv);
}

function main () {
  const args = processArgs(process.argv.slice(2));
  _runServer(args.argv);
}

function saveUser(dir, user) {
  const filepath = resolveDataDir(dir, `${user.userName}.json`);
  fs.writeFileSync(filepath, JSON.stringify(user));
}

function getSavedUser(dir, user) {
  const filepath = resolveDataDir(dir, `${user.userName}.json`);
  if (fs.existsSync(filepath)) {
    return JSON.parse(fs.readFileSync(filepath));
  }
  return null;
}

function getSavedUserOfAppUserId1(dir, appUserId1) {
  const filepath = resolveDataDir(dir, '');
  const users = fs.readdirSync(filepath);
  for (const user of users) {
    if (user.startsWith('.')) {
      continue;
    }
    const savedUser = JSON.parse(fs.readFileSync(path.join(filepath, user)));
    if (appUserId1 === savedUser.appUserId1) {
      return savedUser;
    }
  }
  return null;
}

function getSavedUserOfAppUserId2(dir, appUserId2) {
  const filepath = resolveDataDir(dir, '');
  const users = fs.readdirSync(filepath);
  for (const user of users) {
    if (user.startsWith('.')) {
      continue;
    }
    const savedUser = JSON.parse(fs.readFileSync(path.join(filepath, user)));
    if (appUserId2 === savedUser.appUserId2) {
      return savedUser;
    }
  }
  return null;
}

function clearSaveUser(dir) {
  const filepath = resolveDataDir(dir, '');
  const users = fs.readdirSync(filepath);
  for (const user of users) {
    if (user.startsWith('.')) {
      continue;
    }
    fs.unlinkSync(path.join(filepath, user));
  }
}

function resolveDataDir(dir, file) {
  if (path.isAbsolute(dir)) {
    return path.join(dir, file);
  }
  const pwd = process.env.INIT_CWD;
  return path.join(pwd, dir, file);
}

function createToken(privateKey, seconds) {
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + seconds,
    },
    privateKey,
    { algorithm: "RS256" }
  );
  return token;
}

async function verifyToken(key, token) {
  return new Promise(function (resolve, reject) {
    jwt.verify(token, key, function (err, decoded) {
      if (err) {
        reject(err);
        return;
      }
      resolve(decoded);
    });
  });
}

module.exports = {
  runServer,
  main,
};

if (require.main === module) {
  main();
}
