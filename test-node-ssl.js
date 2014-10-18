var tls       = require('tls');
var fs        = require('fs');
var path      = require('path');
var fork      = require('child_process').fork;
var assert    = require('assert');
var constants = require('constants');

var async     = require('async');
var debug     = require('debug')('test-node-ssl');

var common = require('./common');

var SSL2_COMPATIBLE_CIPHERS = 'RC4-MD5';

var CMD_LINE_OPTIONS = [null, "--enable-ssl2", "--enable-ssl3"];
var SECURE_PROTOCOLS = [null, 'SSLv2_method', 'SSLv3_method'];

function testSetupsCompatible(serverSetup, clientSetup) {

  if (serverSetup.secureProtocol &&
      SECURE_PROTOCOLS.indexOf(serverSetup.secureProtocol) !==
      CMD_LINE_OPTIONS.indexOf(serverSetup.cmdLine)) {
    // A secureProtocol that is incompatible with command line options had been mentioned,
    // the connection between client an server will fail for sure.
    return false;
  }

  if (clientSetup.secureProtocol &&
      SECURE_PROTOCOLS.indexOf(clientSetup.secureProtocol) !==
      CMD_LINE_OPTIONS.indexOf(clientSetup.cmdLine)) {
    // A secureProtocol that is incompatible with command line options had been mentioned,
    // the connection between client an server will fail for sure.
    return false;
  }

  if ((serverSetup.secureProtocol && clientSetup.secureProtocol) &&
      (serverSetup.secureProtocol !== clientSetup.secureProtocol)) {
    // The server and/or the client explicitely set a protocol, but they are not compatible,
    // the connection will fail for sure
    return false;
  }

  if (clientSetup.secureProtocol &&
    CMD_LINE_OPTIONS.indexOf(serverSetup.cmdLine) !==
    SECURE_PROTOCOLS.indexOf(clientSetup.secureProtocol)) {
    // The client specifies a secure protocol that is not enabled by the server,
    // the connection will fail for sure
    return false;
  }

  if (serverSetup.secureProtocol &&
    CMD_LINE_OPTIONS.indexOf(clientSetup.cmdLine) !==
    SECURE_PROTOCOLS.indexOf(serverSetup.secureProtocol)) {
    // The server specifies a secure protocol that is not enabled by the client,
    // the connection will fail for sure
    return false;
  }

  if (((clientSetup.secureProtocol === 'SSLv2_method' && serverSetup.secureProtocol === null) ||
      (clientSetup.secureProtocol === null && serverSetup.secureProtocol === 'SSLv2_method')) &&
      (clientSetup.ciphers !== SSL2_COMPATIBLE_CIPHERS || serverSetup.ciphers !== SSL2_COMPATIBLE_CIPHERS)) {
    return false;
  }

  return true;
}

function createTestsSetups() {

  var serversSetup = [];
  var clientsSetup = [];

  CMD_LINE_OPTIONS.forEach(function (cmdLineOption) {
    SECURE_PROTOCOLS.forEach(function (secureProtocol) {

      var serverSetup = {cmdLine: cmdLineOption, secureProtocol: secureProtocol};
      if (secureProtocol === 'SSLv2_method') {
        // Specific ciphers compatible with SSLv2 are needed, default ciphers
        // are not compatible with SSLv2
        serverSetup.ciphers = SSL2_COMPATIBLE_CIPHERS;
      }
      serversSetup.push(serverSetup);

      clientsSetup.push({cmdLine: cmdLineOption, secureProtocol: secureProtocol});
    })
  });

  var testSetups = [];
  serversSetup.forEach(function (serverSetup) {
    clientsSetup.forEach(function (clientSetup) {
      var testSetup = {server: serverSetup, client: clientSetup };

      var successExpected = false;
      if (testSetupsCompatible(serverSetup, clientSetup)) {
        successExpected = true;
      }
      testSetup.successExpected = successExpected;

      testSetups.push(testSetup);
    });
  });

  return testSetups;
}

function runServer(secureProtocol, ciphers) {
  debug('Running server!');

  var keyPath = path.join(common.fixturesDir, 'agent.key');
  var certPath = path.join(common.fixturesDir, 'agent.crt');

  var key = fs.readFileSync(keyPath).toString();
  var cert = fs.readFileSync(certPath).toString();

  var server = tls.Server({ key: key,
                            cert: cert,
                            ca: [],
                            ciphers: ciphers,
                            secureProtocol: secureProtocol
                          });

  server.listen(common.PORT, function() {
    process.on('message', function onChildMsg(msg) {
      if (msg === 'close') {
        server.close();
        process.exit(0);
      }
    });

    process.send('server_listening');
  });

  server.on('error', function onServerError(err) {
    debug('Server error: ' + err);
    process.exit(1);
  });

  server.on('clientError', function onClientError(err) {
    debug('Client error on server: ' + err);
    process.exit(1);
  });
}

function runClient(secureProtocol) {
  debug('Running client!');

  var con = tls.connect(common.PORT,
                        {
                          rejectUnauthorized: false,
                          secureProtocol: secureProtocol
                        },
                        function() {

    // TODO jgilli: test that sslProtocolUsed is at least as "secure" as
    // "secureProtocol"
    var sslProtocolUsed = con.getVersion();
    debug('Protocol used: ' + sslProtocolUsed);

    process.send('client_done');
  });

  con.on('error', function(err) {
    debug('Client could not connect:' + err);
    process.exit(1);
  });
}

function processSslOptions(argv){
  var options = {
    secureProtocol: null,
    ciphers: null
  };

  argv.forEach(function (arg) {
    var key;
    var value;

    var keyValue = arg.split(':');
    var key = keyValue[0];

    if (keyValue.length == 2) {
      value = keyValue[1];
    }

    options[key] = value;
  });

  return options;
}

function checkTestExitCode(testSetup, serverExitCode, clientExitCode) {
  if (testSetup.successExpected) {
    assert.equal(serverExitCode, 0);
    assert.equal(clientExitCode, 0);
    debug('Test succeeded as expected!');
  }
  else {
    assert.ok(serverExitCode !== 0 || clientExitCode !== 0);
    debug('Test failed as expected!');
  }
}

function forkTestProcess(processType, testSetup) {
  var argv = [ processType ];

  if (testSetup.secureProtocol) {
    argv.push('secureProtocol:' + testSetup.secureProtocol);
  } else {
    argv.push('secureProtocol:');
  }

  if (testSetup.ciphers) {
    argv.push('ciphers:' + testSetup.ciphers);
  } else {
    argv.push('ciphers:');
  }

  var forkOptions;
  if (testSetup.cmdLine) {
    forkOptions = {
      execArgv: [ testSetup.cmdLine ]
    }
  }

  return fork(process.argv[1],
              argv,
              forkOptions);
}

var agentType = process.argv[2];
if (agentType === 'client' || agentType === 'server') {
  var sslOptions = processSslOptions(process.argv);

  if (agentType === 'client') {
    runClient(sslOptions.secureProtocol);
  } else if (agentType === 'server') {
    debug('ciphers:' + sslOptions.ciphers);
    runServer(sslOptions.secureProtocol, sslOptions.ciphers);
  }
} else {
  /*
   * This is the tests driver process.
   *
   * It forks itself twice for each test. Each of the two forked processees are
   * respectfully used as an SSL client and an SSL server. The client and server
   * setup their SSL connection as generated by the "createTestsSetups"
   * function. Once both processes have exited, the tests driver process compare
   * both client and server exit codes with the expected test result of the test
   * setup. If they match, the test is successful, otherwise it failed.
   */
  var testSetups = createTestsSetups();

  debug('Tests setups:');
  debug(JSON.stringify(testSetups, null, " "));
  debug();

  async.eachSeries(testSetups, function (testSetup, testDone) {

    var clientSetup = testSetup.client;
    var serverSetup = testSetup.server;

    if (clientSetup && serverSetup) {
      debug('Starting new test!');

      debug('client setup:');
      debug(clientSetup);

      debug('server setup:');
      debug(serverSetup);

      debug('Success expected:' + testSetup.successExpected);

      var serverExitCode;

      var clientStarted = false;
      var clientExitCode;

      var serverChild = forkTestProcess('server', serverSetup);
      assert(serverChild);

      serverChild.on('message', function onServerMsg(msg) {
        if (msg === 'server_listening') {
          debug('Starting client!');
          clientStarted = true;

          var clientChild = forkTestProcess('client', clientSetup);
          assert(clientChild);

          clientChild.on('exit', function onClientExited(exitCode) {
            debug('Client exited with code:' + exitCode);

            clientExitCode = exitCode;
            if (serverExitCode != null) {
              checkTestExitCode(testSetup, serverExitCode, clientExitCode)
              return testDone();
            } else {
              if (serverChild.connected) {
                serverChild.send('close');
              }
            }
          });

          clientChild.on('message', function onClientMsg(msg) {
            if (msg === 'client_done' && serverChild.connected) {
              serverChild.send('close');
            }
          })
        }
      });

      serverChild.on('exit', function onServerExited(exitCode) {
        debug('Server exited with code:' + exitCode);

        serverExitCode = exitCode;
        if (clientExitCode != null || !clientStarted) {
          checkTestExitCode(testSetup, serverExitCode, clientExitCode);
          return testDone();
        }
      });

    }
  }, function allTestsDone(err, results) {
    console.log('All tests done!');
  });
}
