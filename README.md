<p align="center">
  <img src="logo.png" title="JuNe BackServer" width="300" height="194">
</p>

# [JuNe BackServer](https://github.com/EduardoRuizM/june-backserver "JuNe BackServer")
JuNe BackServer is a Node.js module to create minimalist web frameworks, RESTful API, APPs or backends with Routing and JSON Web Token with session control.
In just 1 file and 22 Kb without dependencies, instead of 630 files, 133 folders and 2.4 Mb (Express + JWT + ws).

# 🏅 8 in 1
#### 1. Routing endpoints response to client request and Middleware
#### 2. JSON Web Token with expiration control
#### 3. Files upload (normal or large)
#### 4. Send Emails
#### 5. WebSockets and Server-Sent Events (SSE) support
#### 6. Captcha (hidden) to avoid spam
#### 7. Google Authenticator
#### 8. Stripe and PayPal payments support

![22 Kb](https://img.shields.io/github/size/EduardoRuizM/june-backserver/backserver.js) ![NPM Downloads](https://img.shields.io/npm/dt/june-backserver)

# Everything you need to build your backend

✔ Create a HTTP or HTTPS server (IPv4 / IPv6).

✔ Routing for GET, POST, PUT, PATCH, DELETE or (default) and with Middleware.

✔ JSON Web Token auto-updated and integrated for ease of use directly in the backend.

✔ Token expiration or forever.

✔ Ready for files/folder upload (small or large sent with chunks from FileReader).

✔ Email delivery support for all MIME types.

✔ WebSockets (ws and secure wss) and Server-Sent Events protocol (SSE) support.

✔ Captcha (hidden) form security support.

✔ Google Authenticator for Two-factor authentication (2FA).

✔ Send payments to Stripe or PayPal.

✔ Support for HTTP/2.

#### 👉 Try JavaScript framework for frontend [JuNe PaulaJS](https://github.com/EduardoRuizM/june-paulajs "JuNe PaulaJS")
#### Also [JuNe WebServer](https://github.com/EduardoRuizM/june-webserver "JuNe WebServer")

# Author
[Eduardo Ruiz](https://github.com/EduardoRuizM) <<eruiz@dataclick.es>>

# JuNe / JUst NEeded Philosophy
1. **Source code using less code as possible**
  So you can understand code and find bugs easier.
2. **Few and optimized lines is better**
  Elegant design.
3. **Avoid external dependencies abuse/bloated, and possible third-party bugs**
  Less files size, better and faster to the interpreter.
4. **Clear and useful documentation with examples and without verbose**
  Get to the point.
5. **Avoid showing unsolicited popups, notifications or messages in frontend**
  For better User eXperience.
6. **Simple UI**, without many menus/options and with few clicks to get to sites.
7. Consequences of having a lot of code (and for simple things): Having to work and search through many files and folders with a lot of wasted time, successive errors due to missing unknown files, madness to move a code to another project, errors due to recursive dependencies difficult to locate, complexity or impossibility to migrate to new versions, unfeasibility to follow the trace with so much code, risk of new errors if the functionality is extended, problems not seen at the first sight, general slowness in the whole development due to excessive and unnecessary code.

# Installation
Using npm package manager `npm install june-backserver`
Or globally to use in more projects `npm install -g june-backserver`

## 🛑 Token parameter is mandatory to encrypt JSON token with a private key.
### You must generate one and store in your project in config or .env file.
So, if you are going to need session token, run this code to get a token:
```
console.log(require('crypto').generateKeyPairSync('rsa', {modulusLength: 1024}).privateKey.export({type: 'pkcs1', format: 'der'}).toString('base64'));
```

#### 💡 Have a look to [JuNeDNS Backend](https://github.com/EduardoRuizM/junedns-backend "JuNeDNS Backend") (and the source code) to see JuNe BackServer in full operation

# Using JuNe BackServer
Define a const with **BackServer** class and as parameter an object with these parameters:
```
const backserver = require('june-backserver');
const app = backserver({url: 'http://myapp.com:8180'});
app.createServer();
```
| Parameter | Definition | Required | Default | Sample |
| --- | --- | :---: | --- | --- |
| url | URL (and port) for running | ✔ | http://localhost:8180 | - |
| ipv6 | Enable IPv6 with IPv4, or just IPv4 | - | true | - |
| cert | SSL cert file path | - | - | cert.pem |
| key | SSL key file path | - | - | key.pem |
| http2 | Use HTTP/2 (certs required) | - | 0 | 1 |
| token | Generated private key | ✔ | - | MIICXQIBAAKBgQDL0Gm... |
| expiry | Token expiration in seconds, or -1 for no expiration | ✔ | 900 | - |
| userfield | User field to delete if token expiration | - | uid | - |
| cors | CORS allow origin | ✔ | * | https://myfrontend.tld |
| before | Middleware function to be called before (HTTP) | - | - | before(req, res, next) |
| after | Middleware function to be called after (HTTP) | - | - | after(req, res) |
| beforews | Middleware function to be called before (WebSockets) | - | - | beforews(req, data, next) |
| afterws | Middleware function to be called after (WebSockets) | - | - | afterws(req, clients) |
| ssetime | Server-Sent Events refresh milliseconds | - | 2000 | - |
| messages | Messages for check params and login | - | {missing: ´Missing fields´, login: ´Please login´}  | - |

- When you create the JuNe BackServer **app**, you can store your variables in object `app.session`
- Parameters sent in body for POST using JSON (default) or multipart/form-data.
- Returned variables in JSON.
- You can easily read URL params with `req.params[NAME]` sample from `/users/:NAME`
- You can easily read HEADER params with `req.headers[NAME]`
- You can easily read GET URLSearchParams with `req.getparams.get(NAME)`
- You can easily read GET object with `req.getobj[NAME]`
- You can easily read POST params with `req.body[NAME]`
- You can easily read current client IP with `req.ip`
- userfield parameter is the name of the user id in session to delete when token expires.
- Middleware to call a function before or after the main request.
- JuNe BackServer integrates 2 checking default functions for required POST parameters and login.
- Texts for the 2 checking functions are in messages parameter.
- There are 2 events for listening and errors.
- (default) is the string route (always as GET) if no other routes found.
- You can define wildcard URL parameters in pathname with : as prefix `/users/:NAME/history/:DATE`
- Default HTTP return status is 200.
- Updated x-access-token header is returned from JuNe BackServer each time (due to new expiry) and must be sent again by caller.
- Caller / frontend must store x-access-token in sessionStorage (never GET param), and deleted when logout.
- Integrated upload system for small or chunked files.
- Captcha (hidden) security functions for forms.
- Don´f forget `app.createServer();` to launch the server app.

✔️JuNe BackServer detects if SSL certificates are renewed (different datetime) and restarts automatically.

```
const backserver = require('june-backserver');

// Initialize
const app = backserver({url: 'http://localhost:8180'})
		.on('listening', address => console.log('JuNe BackServer running', address))
		.on('error', err => console.error(err));

app.get('/myroute', (req, res) => {
  console.log('My route');
});

app.post('/domains/:did/records/:rid', (req, res) => {
  res.setHeader('My-Header', 'I want to add this header');
  console.log(`Parameter ${req.params.did} and ${req.params.rid}`);
});

app.get('(default)', (req, res) => {
  console.log('Not implemented');
});

app.createServer();
```

## HTTP request functions
Each **HTTP** function you define receives 2 parameters: **req** (request) and **res** (response).
Sample:
```
app.get('/myendpoint', (req, res) => {
});
app.post('/myendpoint', (req, res) => {
});
```

**status** HTTP code is always returned in the response, as well as in the header, so in *fetch* when call *response.json()* you can get it´s value.

## Routing
You can use a normal address like `/myendpoint` or you can define an address with variables like `/myendpoint/:id/edit/:myparam` then if URL is `/myendpoint/74/edit/23` you get these parameters as `req.params.id = 74` and `req.params.myparam = 23`

## Values
| Value | Type | Definition |
| --- | --- | --- |
| req.status | Integer | HTTP response status code (default-ok **200**) |
| req.url | String | URL address |
| req.method | String | HTTP method (get, post, put, patch, delete) |
| req.headers | Object | HTTP headers |
| req.params | Object | Parameters from URL (as */users/:id*) |
| req.getparams | URLSearchParams | GET parameters as URLSearchParams |
| req.getobj | Object | GET parameters as object |
| req.content | Object | Content to be returned in the response (in JSON) |
| req.body | Object | POST variables received in JSON |
| req.ip | String | Client IP address |
| app.session | Object | Decoded variables from session token |

### Sample
```
const backserver = require('june-backserver');

const app = backserver({url: 'http://localhost:8180'}).on('listening', address => console.log('JuNe BackServer running', address))


app.get('/myendpoint/:id', (req, res) => {
  console.log('Id', req.params.id, 'MyVar', req.getparams.get('myvar'), 'MyVar (as object)', req.getobj.myvar);
});

app.createServer();
```
Test it: `curl -v -X GET -H "Content-Type: application/json" http://localhost:8180/myendpoint/74?myvar=23`

## Middleware functions (HTTP)
**before(req, res, next)** Optional function to be called before the main request.
- **req** The request (with the values for status, getparams, content, body, ip...).
- **res** The response.
- **next** boolean value (default *true*) to be changed to *false* in case you don´t want to call the main request.

You could use this function to load user, logs or assign language.
Sample `const app = backserver({before: async function(req, res, next) { await iniSession(req, res, next); }})`

**after(req, res)** Optional function to be called after the main request.
- **req** The request.
- **res** The response.
Sample `const app = backserver({after: myAfterFunction})`

## Upload files
An integrated upload system allows you to handle files easily, you can receive one or several files, depending on input configuration.

### Normal files
An array is received for each file and contains the objects: name (filename), type (content-type), size, (width)x(height) if image, and content.
```
app.post('/upload', (req, res) => {

  // Show 'myfile' file variable
  // If binary file such as image, save it in binary: fs.writeFileSync('myname', f.content, 'binary');
  if(req.body.myfile) {
    for(let f of req.body.myfile)
      console.log(`File name: '${f.name}', content-type: ${f.type}, size: ${f.size}` + ((f.width && f.height) ? `, image: ${f.width}x${f.height}` : '')); //Content in: f.content
  }
});
```

### Chunked files
Variables are received for each chunk using PUT.
Compatible and designed for **[JuNe PaulaJS](https://github.com/EduardoRuizM/june-paulajs "JuNe PaulaJS") JavaScript framework** (with examples), although you could also perform the same functionallity in your own frontend with the same variables.

```
app.put('/upload', (req, res) => {

  // Show 'myfile'
  // internal function jPaufileUpload returns:
  //	false				= if no file
  //	true				= if still loading
  //	array_objects	= when ends
  //	So, when ends, you must move or do anything with file located in temp folder
  // array_objects are: name (variable_name), number (file uploaded number) and file (file_path)
  // You can upload several files, so number from 0 to n, and name "myfile" for first, "myfile_1" for second, "myfile_2" for third...

  // Files uploaded to OS temp folder, delete these files if exist on BackServer init, or in the next upload if modification file great than 30 minutes

  // Variables in each file upload:
  //	myfile_ID	= Upload Id (to differentiate the same upload in each file and connection / section)
  //	myfile_RND	= Unique randon number (second code to differentiate the same upload in each file)
  //	myfile_NAME	= File name
  //	myfile_TYPE	= Content-Type
  //	myfile_SIZE	= File size
  //	myfile_WIDTH	= Image width (if file is image)
  //	myfile_HEIGHT	= Image height (if file is image)
  //	myfile_PATH	= File path (webkitRelativePath: relative path to selected directory)
  //	myfile_PART	= File part
  //	myfile_PARTS	= File total parts

  let f = app.jPaufileUpload(req, 'myfile');
  if(f === false) console.error('No files in myfile');
  if(f === true) console.log('Still loading myfile');

  if(f instanceof Object) console.log(`Large file number '${f.number}' uploaded in file '${f.file}'`);
});
```

## Send Email
To send an Email by example from a contact form.
It uses **sendmail** which is a mail transfer agent (MTA), common in Linux servers, or install it with `apt-get install sendemail`
For Windows try this [sendmail](https://github.com/sendmail-tls1-2/main "sendmail") and change path in JuNe BackServer. [Direct ZIP download](https://github.com/sendmail-tls1-2/main/raw/master/Sendmail_v33_TLS1_2.zip "Direct ZIP download").

Support all Email types: text only, text + HTML, text + attachments, text + HTML + attachments, text + HTML with embeded images, and  text + HTML with embeded images + attachments.

Also CC or BCC support, send IP (from *req.ip*), and convert HTML to text.

To add attachments and/or embeded images (inside HTML), use object:
```
{ files: [
	{name: 'myfile.ext', type: 'content-type', content: 'content'}
  ],
  images: [
	{name: 'myimage.ext', type: 'image/ext', content: 'content', code: 'myimgcode'}
  ]
}
```

- *files* is an array for attached files with **name** (FileName), **type** (Content-Type) and **content**
- *images* is an array for embeded images with **name** (FileName), **type** (Content-Type), **content** and **code** with the code used in the HTMLImage `<img src="cid:myimgcode">` for *code = myimgcode*

Function:
`app.mailSend(from_name, from_email, to_name, to_email, subject, text, html = '', ip = '', attach = {}, cc = '', bcc = '')`

Function to get Content-Type using file extension:
`app.file2type(fileName);`

Text Email:
```
app.mailSend('FromName', 'from@domain.tld', 'ToName', 'to@mydomain.tld', 'My Subject', 'My text', '', req.ip);
```

HTML Email:
```
app.mailSend('FromName', 'from@domain.tld', 'ToName', 'to@mydomain.tld', 'My Subject', '', '<b>My text</b>', req.ip);
```

Text Email with attachment:
```
let attach = {files: [{name: 'myfile.zip', type: app.file2type('myfile.zip'), content: fs.readFileSync('myfile.zip')}]};
app.mailSend('FromName', 'from@domain.tld', 'ToName', 'to@mydomain.tld', 'My Subject', 'My text', '', req.ip, attach);
```

HTML Email with embeded image:
```
let attach = {images: [{code: 'myimgcode', name: 'myimage.jpg', type: app.file2type('myimage.jpg'), content: fs.readFileSync('myimage.jpg')}]};
app.mailSend('FromName', 'from@domain.tld', 'ToName', 'to@mydomain.tld', 'My Subject', '', 'My HTML text <img src="cid:myimgcode">', req.ip, attach);
```

You can use both for multiple files and multiple images.

## WebSockets
Easy support for this two-way interactive communication protocol between server/backend and browser.
All communications must be JSON.
In tokens with expiration, expiration date is not updated, as HTTP does, for security.
The token is sent at the beginning of the connection by GET, then it should be sent updated in the object of each request with the variable *accessToken*:
`socket.send({accessToken: this.config.data._token})`

- Reusing the same URL and port that HTTP server.
- Create an endpoint with 3 parameters: req, clients, options
  - **req** is the request, with values:
    - *params*: URL params (for */myendpoint/:id*)
    - *getparams*: GET params (for */myendpoint?myparam=1*)
    - *body*: received JSON.
    - *headers*: HTTP headers.
    - *ip*: client IP.
  - **clients** are all active clients, you can apply a filter if needed with: *clients = clients.filter()*
  - **options** an object with 2 values:
    - **withToken** boolean value, default false, does not send if clients have an active and not expired token.
    - **notMe** boolean value, default false, exclude client sender.

Sample:
```
app.get('/mywebsocket', (req, clients, options) => {
});
```

**clients** is an object with:
  - **key** unique identifier from Sec-WebSocket-Key.
  - **socket** TCP socket per client to send messages.
  - **token** Decoded session token sent in URL via GET parameter with *accessToken* variable name.
    - This token works in the same way as *X-Access-Token* HTTP header.
    - To update token, send it in your frontend call with *accessToken* variable name.
    - You can check the information of each user on the token.

#### Functions
**app.getClients(withToken, clients)** Retrieves all connected clients:
- *withToken*: optional boolean parameter to get only with active and not expired token clients.
- *clients*: optional clients or get current connected clients.

**app.sendWS(obj, clients)** Send obj to clients.

#### Middleware functions
**beforews(req, data, next)** Optional function to be called before the WebSocket main request.
- **req** The request (with the values for status, getparams, content, body, ip...).
- **data** JSON object with the received data.
- **next** boolean value (default *true*) to be changed to *false* in case you don´t want to call the main request.

You could use this function to load user, logs or assign language.
Sample `const app = backserver({beforews: async function(req, data, next) { await iniSession(req, data, next); }})`

**afterws(req, clients)** Optional function to be called after the WebSocket main request.
- **req** The request.
- **clients** Final active clients.
Sample `const app = backserver({afterws: myAfterWSFunction})`

#### Sample WebSockets
Backend JS file:
```
const backserver = require('june-backserver');

const app = backserver({url: 'http://localhost:8180'}).on('listening', address => console.log('Server', address));

app.get('/mywebsocket', (req, clients, options) => {
  console.log(req.getparams);
  req.content.from = req.headers['sec-websocket-key'];
});

app.createServer();
```

Add to your frontend a WebSocket that receives data, be careful if *e.data* is **PONG** then you must do nothing, it´s due to ping protocol response.
HTML file:
```
<script>
let wsocket;
function wsocketCreate() {
  wsocket = new WebSocket('ws://localhost:8180/mywebsocket?myparam=1');
  wsocket.onmessage = e => {alert(e.data)};
  wsocket.onerror = e => console.error(e);
  // If you want to reconnect in 2 seconds in case of error
  // wsocket.onerror = e => setTimeout(() => wsocketCreate(), 2000);
}
function wsocketSend() {
  wsocket.send(JSON.stringify({msg: 'Hello from client'}));
}
wsocketCreate();
</script>
<input type="button" value="Send Hello" onclick="wsocketSend()">
```

💡 Have a look to [JuNeDNS Frontend](https://github.com/EduardoRuizM/junedns-frontend "JuNeDNS Frontend") that includes a feature using WebSockets,
wich send a notification to all connected clients to notice that a data has been created, updated or deleted, and so the client automatically reloads the content to show it updated,
improving the user experience, and always having on screen all the ´live´ content, which may have been changed by another remote user.
Many software such as Email or cloud storage, use this technology.

## Server-Sent Events (SSE)
Server-Sent Event is a technology for a web page that automatically gets updates from a server.

You must create an endpoint that will be called every **ssetime** milliseconds (default 2000), then if necessary you can change the value of object **req.content** and it will be sent to client, and  in the next iteration the object will be reset.

#### Sample
Backend JS file:
```
const backserver = require('june-backserver');

const app = backserver({url: 'http://localhost:8180'}).on('listening', address => console.log('Server', address));

app.get('/mysse', (req, res) => {
  req.content.msg = new Date();
});

app.createServer();
```

HTML file:
```
<div id="sse"></div>
<script>
const eventSource = new EventSource('http://localhost:8180/mysse');
eventSource.onmessage = e => document.getElementById('sse').innerHTML+= `${e.data}<br>`;
eventSource.onerror = e => {console.error(e); eventSource.close()}
</script>
```

## Captcha (hidden)
To prevent form spamming by bots using function `captcha`
It´s in invisible for users.

1. Create a GET endpoint to receive a key to add to the form:
```
app.get('/captcha', (req, res) => {
  req.content.k = app.captcha();
});
```

2. The frontend must resend this *captcha* key (from *response.k*), expiration is 1 minute.

3. On POST endpoint must check captcha input variable:
```
app.post('/myendpoint', (req, res) => {
  if(!req.body.captcha || !app.captcha(req.body.captcha))
    return;
  // Ok
});
```

The operation is the following, before sending the form by the frontend, it sends a request to the backend that returns a key that is registered in the backend for one minute, the frontend forwards it to the backend and it is verified that it exists.
Since a FormData is used, the captcha key request is done first and then the form submit. Therefore, indicate a different URL in the form action so that the bots waste time there.

## 🞸 Google Authenticator
Add Two-factor authentication (2FA) to your project to improve safety with this multi-factor authentication service that uses the time-based one-time password (TOTP).

1. Users must install the app: [Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2 "Android") or [Apple](https://apps.apple.com/us/app/google-authenticator/id388497605 "Apple")

2. When a user requests the service, a *key* must be generated using:
   `app.googleAuthenticator().code(nameProject, codeUser)`
   **nameProject**: is the name of your app or project to show to the user.
   **codeUser**: is a unique code to identify the user, as an Email.
   Returns an object with 2 values:
   **key**: is the user unique key to store in your users database, also, the user can manually add this key directly in Google Authenticator.
   **url**: is the URL to add the key automatically by scanning a QR code to Google Authenticator.
   You can create a QR image, and show it for the user to scan on your frontend by installing a QR generator on your server or with a third-party utility:
   Using QRServer: `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(url)}`

3. On the login page, an input is displayed for the user´s code/Email, and another input to type the value token generated from Google Authenticator.
   Check it with boolean function:
   `app.googleAuthenticator().verify(token, key)`
   **token**: The token typed by user on the login page.
   **key**: The key stored for the user in the previous step.

## Stripe
Send payments to Stripe in a promise with **Stripe(secret, token, total, desc, cur)** and returns JSON response.

**secret** Stripe secret credential
**token** Stripe token credential
**total** Total amount
**desc** Order description
**cur** Currency code (default *eur*)

`app.Stripe('sk_live_XXX...', 'pk_live_XXX...', 124.56, 'My order', 'usd').then(r => console.log(r));`

## PayPal
Send payments to PayPal in a promise with **Paypal(clientId, clientSecret, total, desc, cur)** and returns JSON response.

**clientId** PayPal clientId
**clientSecret** PayPal clientSecret
**total** Total amount
**desc** Order description
**cur** Currency code (default *EUR*)

`app.PayPal(myClientId, myClientSecret, 124.56, 'My order', 'USD').then(r => console.log(r));`

## Sample using MySQL for users login
```
const backserver = require('june-backserver');
const mysql = require('mysql');
const util = require('util');

// Database for synchronous queries
const db = mysql.createConnection({host: '127.0.0.1', user: 'user', password: '', database: 'dbname', port: 3306});
const query = util.promisify(db.query).bind(db);

// uid is value from app.userfield
// Middleware before() checks user if app.session.uid exists
// app.session.uid deleted if token expired
// If ok then store user for future use in app.session.user (remove password for security)
// So we have app.session.uid for login user id, and app.session.user with user object
// Check if language passed by 'lang' GET parameter and store in app.session.lang
async function iniSession(req, res, next) {
  // You could put here a log system, at this moment we have all necessary data and variables

  if(req.getparams.has('lang')) {

    app.session.lang = req.getparams.get('lang');
    // Maybe you must update here object 'app.messages'

  } else if(!session.lang)
    app.session.lang = 'en-US';

  if(!app.session.uid)
    return;

  const result = await query('SELECT * FROM users WHERE id=? LIMIT 1', app.session.uid);
  if(result.length) {

    app.session.user = result[0];
    delete app.session.user.passwd;
  }
}

// Generic function to CRUD
// So we return status 200 and content request if no errors
// Or return 400 and error message
async function dbQuery(req, res, q, v) {
  try {

    req.status = 200;
    return await query(q, v);

  } catch(err) {

    req.status = 400;
    if(err.sqlMessage)
      err = err.sqlMessage;

    console.error(err);
    content.error = err;

  } finally {

    // Remember we have app.lang to use here in a language text function
    if(req.status >= 400)
      req.content.message = 'Bad Request';
  }
}

// Initialize
const app = backserver({
			url:		'http://localhost:8180',
			token:		'MIICXQIBAAKBgQDL0Gm...',
			userfield:	'uid',
			messages:	{missing: 'Missing fields', login: 'Please login'},
			before:		async function(req, res, next) { await iniSession(req, res, next); }
		})
		.on('listening', address => console.log('JuNe BackServer running', address))
		.on('error', err => console.error(err));

app.post('/login', (req, res) => {
  // We use checkParams with variables object (key: name) to check or return 400
  // status: 400 and body: {"status": 400, "message": "Missing fields Code, Password"}
  if(!app.checkParams({code: 'Code', 'passwd': 'Password'}))
    return;

  const result = await dbQuery(req, res, 'SELECT * FROM users WHERE code=? LIMIT 1', req.body.code);
  if(result.length) {

    // Check password using scryptSync and first 32 characters of token, but you can use your own
    if(result[0].passwd === crypto.scryptSync(req.body.passwd, app.token.substring(0, 32), 32).toString('hex'))
      // If ok then app.session.uid with user id
      app.session.uid = result[0].id;
    else
      req.content.message = 'Invalid user or password';

  } else {

    req.status = 404;
    req.content.message = 'User not found';
  }
});

app.get('/users', (req, res) => {
  // To retrieve all users, login is required or status 401 and message app.messages.login is returned
  if(!app.checkLogin())
    return;

  // status: 200 and body: {"status": 200, "users": [{"id": 1, "code": "john"}, {"id": 2, "code": "peter"}]}
  req.content.users = await dbQuery(req, res, 'SELECT id, code FROM users');
});

app.createServer();
```

### 🎓 Good practices
- Never trust on the data received or its structure, always check to avoid errors or security risks.
- Data may not be received due to a communication failure, be incomplete or manipulated from origin.
- Check everything even if it seems redundant, remember that a simple error can stop the execution of your program.
- Don´t forget to check user permissions.
- JuNe BackServer can´t check everything to prevent the code from growing, so keep an eye on everything you do and watch the error console.
- Store backend files in a non-public folder, outside Internet access, to avoid security breaches.
- Use Optional chaining operator ?. the expression evaluates to undefined instead of throwing an error **myobject?.mymethod?.mymethod2**
- Use Nullish coalescing operator to set a (default) return value if null or undefined **myvar = myvar ?? mydefault**
- Use one function per call to execute the code, do not use several functions for the same call, as this is confusing and not allowed.

## Test
With **cURL** (you don´t need Postman):
- Login:
  `curl -v -X POST -H "Content-Type: application/json" -d "{\"user\": \"USER\", \"passwd\": \"\"}" http://localhost:8180/login`
- Send request:
  `curl -v -X GET -H "Content-Type: application/json" -H "x-access-token: TOKEN" http://localhost:8180/users`

### You can use HTTP to proxy HTTPS with Nginx:
```
server {
	listen		443 ssl;
	listen		[::]:443 ssl; #http3?
	server_name	mybackend.tld;

	ssl_certificate		ACME_PATH/mydomain.tld/fullchain.cer;
	ssl_certificate_key	ACME_PATH/mydomain.tld/mydomain.tld.key;
	ssl_protocols			TLSv1.2 TLSv1.3;

	location / {
		proxy_set_header	X-Forwarded-For $remote_addr;
		proxy_set_header	Host $http_host;
		proxy_pass		http://127.0.0.1:8180;
	}
}
```

## Certificates for SSL localhost
Generate a self-signed certificate, only for localhost development purposes.
Avoid browser warning ´Potential Security Risk´ with a Certification Authority entity (CA).
1) Create file `localhost.ext` (add more IPs or domains if needed):
```
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
```
2) Generate certificates to use on your HTTP server `localhost.crt` and `localhost.key`
```
openssl genrsa -out CA.key -des3 2048
openssl req -x509 -sha256 -new -nodes -days 3650 -key CA.key -out CA.pem
openssl genrsa -out localhost.crypted.key -des3 2048
openssl req -new -key localhost.crypted.key -out localhost.csr
openssl x509 -req -in localhost.csr -CA CA.pem -CAkey CA.key -CAcreateserial -days 3650 -sha256 -extfile localhost.ext -out localhost.crt
openssl rsa -in localhost.crypted.key -out localhost.key
```
3) To avoid warning: Browser ➜ Certificates ➜ Import ➜ Authorities ➜ `CA.pem`

# The Making Of JuNe BackServer
(JuNe Philosophy) A few lines for...

### Generate key pair
```
const token = crypto.generateKeyPairSync('rsa', {modulusLength: 1024}).privateKey.export({type: 'pkcs1', format: 'der'});
const public_key = crypto.createPublicKey({key: token, type: 'pkcs1', format: 'der'});
const private_key = crypto.createPrivateKey({key: token, type: 'pkcs1', format: 'der'});
```

### Encrypt session token with expiry
```
session._exp = Math.round((new Date()).getTime() / 1000) + expiry;
header['x-access-token'] = crypto.publicEncrypt({key: public_key, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(JSON.stringify(session))).toString('base64');
```

### Decrypt token
```
session = JSON.parse(crypto.privateDecrypt({key: private_key, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(header['x-access-token'], 'base64')).toString('utf-8'));
if(session._exp < Math.round((new Date()).getTime() / 1000))
    session = {};
```

### Convert from route pathname to :variables and call functions
The heart of all routing system is just a few lines (and mainly everything on line 6):
```
// pathname = '/endpoint/hello/other/6';
let routes = {get: [], post: [], put: [], patch: [], delete: []};
// routes.get.push({route: '/endpoint/:param/other/:second', func: (req, res) => {}});
let gs;
let i = routes[method].findIndex((e) => {
  let rg = new RegExp('^' + e.route.replace(/:([^/]+)/g, '(?<$1>[^/]+)') + '$');
  gs = pathname.match(rg);
  return gs;
});
let params = gs?.groups;
if(i > -1)
  routes[method][i].func(req, res, next);
```

### JuNe BackServer was developed initially for [JuNeDNS Backend](https://github.com/EduardoRuizM/junedns-backend "JuNeDNS Backend") and [JuNeDNS Frontend](https://github.com/EduardoRuizM/junedns-frontend "JuNeDNS Frontend")

# JuNe Development Ecosystem
Everything you need to develop your project:
### Backend
- [JuNe BackServer](https://github.com/EduardoRuizM/june-backserver "JuNe BackServer") With request routing, tokens, file upload, send Emails, WebSockets, SSE and captcha.
- [JuNe WebServer](https://github.com/EduardoRuizM/june-webserver "JuNe WebServer") Web server with HMR.

### Frontend
- [JuNe PaulaJS](https://github.com/EduardoRuizM/june-paulajs "JuNe PaulaJS") Powerful JavaScript framework
- [JuNe CSS](https://github.com/EduardoRuizM/june-css "JuNe CSS") Full responsive CSS library with icons.
