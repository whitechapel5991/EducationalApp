    // Start this client on 5006 port or change `localhostClientPort` variable
    // Start application:
    // ..\client\: npx http-server -p localhostClientPort
    // localhostClientPort is port this client!!!
    //
    // For example:
    // ..\client\: npx http-server -p 5006
    const secureAPI = `https://localhost:5002/api/secure`;
    const identityServer = `https://localhost:5000`;
    const localhostClientPort = 5006;

function log() {
  document.getElementById('results').innerText = '';
  document.getElementById('userLabel').innerHTML = '';

  Array.prototype.forEach.call(arguments, function (msg) {
      if (msg instanceof Error) {
          msg = "Error: " + msg.message;
      }
      else if (typeof msg !== 'string') {
          msg = JSON.stringify(msg, null, 2);
      }

      document.getElementById('userLabel').innerHTML = 'User data:';
      document.getElementById('results').innerHTML += msg + '\r\n';
  });
}

document.getElementById("login").addEventListener("click", login, false);
document.getElementById("api").addEventListener("click", api, false);
document.getElementById("logout").addEventListener("click", logout, false);

const config = {
  authority: identityServer,
  client_id: 'spa',
  redirect_uri: `http://localhost:${localhostClientPort}/callback.html`,
  post_logout_redirect_uri: `http://localhost:${localhostClientPort}/index.html`,
  response_type: 'code',
  aud: 'api',
  scope: 'openid profile email api.read',
};

var mgr = new Oidc.UserManager(config);

mgr.getUser().then(function (user) {
  if (user) {
      document.getElementById("tokenLabel").innerHTML = 'Token:';
      document.getElementById("token").innerHTML = user.access_token + '\r\n';
      log("User logged in", user.profile);
  }
  else {
      document.getElementById("tokenLabel").innerHTML = '';
      document.getElementById("token").innerHTML = '';
      log("User not logged in");
  }
});

function login() {
  mgr.signinRedirect();
}

function api() {
  mgr.getUser().then(function (user) {
      var url = secureAPI;

      var xhr = new XMLHttpRequest();
      xhr.open("GET", url);
      xhr.onload = function () {
        document.getElementById("apiLabel").innerHTML = 'Api result:';
        document.getElementById('apiResults').innerHTML = `Status ${xhr.status} \r\n`;
        document.getElementById('apiResults').innerHTML += JSON.stringify(JSON.parse(xhr.responseText), null, 2);
      }
      xhr.setRequestHeader("Authorization", "Bearer " + user.access_token);
      xhr.send();
  });
}

function logout() {
  mgr.signoutRedirect();
}
