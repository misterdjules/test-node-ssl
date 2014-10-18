var tls       = require('tls');
var fs        = require('fs');
var path      = require('path');
var fork      = require('child_process').fork;
var assert    = require('assert');
var constants = require('constants');
var async     = require('async');

var common = require('./common');

var SSL2_COMPATIBLE_CIPHERS = 'RC4-MD5';

console.log('argv:', process.argv);

function createTestsSetups() {

  function setupsCompatible(serverSetup, clientSetup) {

    if (serverSetup.secureProtocol &&
        secureProtocols.indexOf(serverSetup.secureProtocol) !==
        cmdLineOptions.indexOf(serverSetup.cmdLine)) {
      // A secureProtocol that is incompatible with command line options had been mentioned,
      // the connection between client an server will fail for sure.
      return false;
    }

    if (clientSetup.secureProtocol &&
        secureProtocols.indexOf(clientSetup.secureProtocol) !==
        cmdLineOptions.indexOf(clientSetup.cmdLine)) {
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
      cmdLineOptions.indexOf(serverSetup.cmdLine) !== secureProtocols.indexOf(clientSetup.secureProtocol)) {
      // The client specifies a secure protocol that is not enabled by the server,
      // the connection will fail for sure
      return false;
    }

    if (serverSetup.secureProtocol &&
      cmdLineOptions.indexOf(clientSetup.cmdLine) !== secureProtocols.indexOf(serverSetup.secureProtocol)) {
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

  var cmdLineOptions  = [null, "--enable-ssl2", "--enable-ssl3"];
  var secureProtocols = [null, 'SSLv2_method', 'SSLv3_method'];

  var serversSetup = [];
  var clientsSetup = [];

  cmdLineOptions.forEach(function (cmdLineOption) {
    secureProtocols.forEach(function (secureProtocol) {

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
      if (setupsCompatible(serverSetup, clientSetup)) {
        successExpected = true;
      }
      testSetup.successExpected = successExpected;

      testSetups.push(testSetup);
    });
  });

  return testSetups;
}

function runServer(secureProtocol, ciphers) {
  console.log('Running server!');

  var keyPath = path.join(common.fixturesDir, 'agent.key');
  var certPath = path.join(common.fixturesDir, 'agent.crt');

  var key = fs.readFileSync(keyPath).toString();
  var cert = fs.readFileSync(certPath).toString();

  var server = tls.Server({ key: key,
                            cert: cert,
                            ca: [],
                            //secureOptions: 0,
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
    console.log('Server error: ', err);
    process.exit(1);
  });

  server.on('clientError', function onClientError(err) {
    console.log('Client error on server: ', err);
    process.exit(1);
  });
}

function runClient(secureProtocol) {
  console.log('Running client!');

  var con = tls.connect(common.PORT,
                        {
                          rejectUnauthorized: false,
                          secureProtocol: secureProtocol
                        },
                        function() {
    //assert.equal(con.getVersion(), 'SSLv2');
    console.log('Protocol used: ', con.getVersion());
    process.send('client_done');
  });

  con.on('error', function(err) {
    console.error('Client could not connect:', err);
    process.exit(1);
  });

  /*
  con.on('end', function () {
    process.send('client_done');
  });
  */
}

var agentType = process.argv[2];

if (agentType === 'client' || agentType === 'server') {
  var secureProtocol, ciphers;
  process.argv.forEach(function (argv) {
    var argPair = argv.split(':');
    if (argPair.length == 2) {
      if (argPair[0] === 'secureprotocol') {
        secureProtocol = argPair[1];
      } else if (argPair[0] === 'ciphers') {
        ciphers = argPair[1];
      }
    }
  });

  if (agentType === 'client') {
    runClient(secureProtocol);
  } else if (agentType === 'server') {
    console.log('ciphers:', ciphers);
    runServer(secureProtocol, ciphers);
  }
} else {
  var testSetups = createTestsSetups();
  async.eachSeries(testSetups, function (testSetup, testDone) {

    var clientSetup = testSetup.client;
    var serverSetup = testSetup.server;

    if (clientSetup && serverSetup) {
      console.log('Starting new test!');

      console.log('client setup:');
      console.log(clientSetup);

      console.log('server setup:');
      console.log(serverSetup);

      console.log('successExpected:', testSetup.successExpected);

      var serverExited = false;
      var serverExitCode;

      var clientExited = false;
      var clientStarted = false;
      var clientExitCode;

      function checkExitCode(serverExitCode, clientExitCode) {
        if (testSetup.successExpected) {
          assert.equal(serverExitCode, 0);
          assert.equal(clientExitCode, 0);
          console.log('Test succeeded as expected!');
        }
        else {
          assert.ok(serverExitCode !== 0 || clientExitCode !== 0);
          console.log('Test failed as expected!');
        }
      }

      var serverExecArgv = [ 'server' ];

      if (serverSetup.secureProtocol) {
        serverExecArgv.push('secureprotocol:' + serverSetup.secureProtocol);
      } else {
        serverExecArgv.push('secureprotocol:');
      }

      if (serverSetup.ciphers) {
        serverExecArgv.push('ciphers:' + serverSetup.ciphers);
      } else {
        serverExecArgv.push('ciphers:');
      }

      var serverForkOptions;
      if (serverSetup.cmdLine) {
        serverForkOptions = {
          execArgv: [ serverSetup.cmdLine ]
        }
      }

      var serverChild = fork(process.argv[1],
                             serverExecArgv,
                             serverForkOptions);
      assert(serverChild);

      serverChild.on('message', function onServerMsg(msg) {
        if (msg === 'server_listening') {
          console.log('Starting client!');
          clientStarted = true;

          var clientExecArgv = [ 'client' ];

          if (clientSetup.secureProtocol) {
            clientExecArgv.push('secureprotocol:' + clientSetup.secureProtocol);
          } else {
            clientExecArgv.push('secureprotocol:');
          }

          var clientForkOptions;
          if (clientSetup.cmdLine) {
            clientForkOptions = {
              execArgv: [ clientSetup.cmdLine ]
            }
          }

          var clientChild = fork(process.argv[1],
                                 clientExecArgv,
                                 clientForkOptions);
          assert(clientChild);

          clientChild.on('exit', function onClientExited(exitCode) {
            console.log('Client exited with code:', exitCode);
            clientExitCode = exitCode;
            clientExited = true;
            if (serverExited) {
              checkExitCode(serverExitCode, clientExitCode)
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
        console.log('Server exited with code:', exitCode);
        serverExitCode = exitCode;
        serverExited = true;
        if (clientExited || !clientStarted) {
          checkExitCode(serverExitCode, clientExitCode);
          return testDone();
        }
      });

    }
  }, function allTestsDone(err, results) {
    console.log('All tests done!');
  });
}
