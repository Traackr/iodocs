//
// Copyright (c) 2011 Mashery, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Module dependencies
//
var express     = require('express'),
    util        = require('util'),
    fs          = require('fs'),
    query       = require('querystring'),
    url         = require('url'),
    http        = require('http'),
    https       = require('https'),
    crypto      = require('crypto');

// Configuration
try {
    var configJSON = fs.readFileSync(__dirname + "/config.json");
    var config = JSON.parse(configJSON.toString());
} catch(e) {
    console.error("File config.json not found or is invalid.");
    process.exit(1);
}

//
// Load API Configs
//
var apisConfig;
fs.readFile(__dirname +'/public/data/apiconfig.json', 'utf-8', function(err, data) {
    if (err) throw err;
    apisConfig = JSON.parse(data);
    if (config.debug) {
         console.log(util.inspect(apisConfig));
    }
});

var app = module.exports = express.createServer();

app.configure(function() {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(express.logger());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser());
    app.use(express.session({
        secret: config.sessionSecret
    }));

    app.use(app.router);

    app.use(express.static(__dirname + '/public'));
});

app.configure('development', function() {
    app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function() {
    app.use(express.errorHandler());
});

//
// processRequest - handles API call
//
function processRequest(req, res, next) {
    if (config.debug) {
        console.log(util.inspect(req.body, null, 3));
    };

    var reqQuery = req.body,
        params = reqQuery.params || {},
        methodURL = reqQuery.methodUri,
        httpMethod = reqQuery.httpMethod,
        apiKey = reqQuery.apiKey,
        apiSecret = reqQuery.apiSecret,
        apiName = reqQuery.apiName
        apiConfig = apisConfig[apiName],
        key = req.sessionID + ':' + apiName;

    // Replace placeholders in the methodURL with matching params
    for (var param in params) {
        if (params.hasOwnProperty(param)) {
            if (params[param] !== '') {
                // URL params are prepended with ":"
                var regx = new RegExp(':' + param);

                // If the param is actually a part of the URL, put it in the URL and remove the param
                if (!!regx.test(methodURL)) {
                    methodURL = methodURL.replace(regx, params[param]);
                    delete params[param]
                }
            } else {
                delete params[param]; // Delete blank params
            }
        }
    }

    var baseHostInfo = apiConfig.baseURL.split(':');
    var baseHostUrl = baseHostInfo[0],
        baseHostPort = (baseHostInfo.length > 1) ? baseHostInfo[1] : "";

    var paramString = query.stringify(params),
        privateReqURL = apiConfig.protocol + '://' + apiConfig.baseURL + apiConfig.privatePath + methodURL + ((paramString.length > 0) ? '?' + paramString : ""),
        options = {
            headers: apiConfig.headers,
            protocol: apiConfig.protocol + ':',
            host: baseHostUrl,
            port: baseHostPort,
            method: httpMethod,
            path: apiConfig.publicPath + methodURL// + ((paramString.length > 0) ? '?' + paramString : "")
        };

    if (['POST','DELETE','PUT'].indexOf(httpMethod) !== -1) {
        var requestBody = query.stringify(params);
    }

    if (['POST','PUT','DELETE'].indexOf(httpMethod) === -1) {
        options.path += ((paramString.length > 0) ? '?' + paramString : "");
    }

    // Add API Key to params, if any.
    if (apiKey != '' && apiKey != 'undefined' && apiKey != undefined) {
        if (options.path.indexOf('?') !== -1) {
            options.path += '&';
        }
        else {
            options.path += '?';
        }
        options.path += apiConfig.keyParam + '=' + apiKey;
    }

    // Perform signature routine, if any.
    if (apiConfig.signature) {
        if (apiConfig.signature.type == 'signed_md5') {
            // Add signature parameter
            var timeStamp = Math.round(new Date().getTime()/1000);
            var sig = crypto.createHash('md5').update('' + apiKey + apiSecret + timeStamp + '').digest(apiConfig.signature.digest);
            options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
        }
        else if (apiConfig.signature.type == 'signed_sha256') { // sha256(key+secret+epoch)
            // Add signature parameter
            var timeStamp = Math.round(new Date().getTime()/1000);
            var sig = crypto.createHash('sha256').update('' + apiKey + apiSecret + timeStamp + '').digest(apiConfig.signature.digest);
            options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
        }
    }

    // Setup headers, if any
    if (reqQuery.headerNames && reqQuery.headerNames.length > 0) {
        if (config.debug) {
            console.log('Setting headers');
        };
        var headers = {};

        for (var x = 0, len = reqQuery.headerNames.length; x < len; x++) {
            if (config.debug) {
              console.log('Setting header: ' + reqQuery.headerNames[x] + ':' + reqQuery.headerValues[x]);
            };
            if (reqQuery.headerNames[x] != '') {
                headers[reqQuery.headerNames[x]] = reqQuery.headerValues[x];
            }
        }

        options.headers = headers;
    }
    if(options.headers === void 0){
        options.headers = {}
    }

    // If POST, PUT, -or- DELETE
    if (requestBody) {
        options.headers['Content-Length'] = requestBody.length;
        options.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';
    }
    else {
        options.headers['Content-Length'] = 0;
        delete options.headers['Content-Type'];
    }

    if (config.debug) {
        console.log(util.inspect(options));
    };

    var doRequest;
    if (options.protocol === 'https' || options.protocol === 'https:') {
        options.protocol = 'https:'
        doRequest = https.request;
    } else {
        doRequest = http.request;
    }

    if (config.debug) {
      console.log('Protocol: ' + options.protocol);
    }

    // API Call. response is the response from the API, res is the response we will send back to the user.
    var apiCall = doRequest(options, function(response) {
        response.setEncoding('utf-8');

        if (config.debug) {
            console.log('HEADERS: ' + JSON.stringify(response.headers));
            console.log('STATUS CODE: ' + response.statusCode);
        };

        res.statusCode = response.statusCode;

        var body = '';

        response.on('data', function(data) {
            body += data;
        })

        response.on('end', function() {
            delete options.agent;

            var responseContentType = response.headers['content-type'];

            switch (true) {
                case /application\/javascript/.test(responseContentType):
                case /application\/json/.test(responseContentType):
                    if (config.debug) {
                      console.log(util.inspect(body));
                    }
                    break;
                case /application\/xml/.test(responseContentType):
                case /text\/xml/.test(responseContentType):
                default:
            }

            // Set Headers and Call
            req.resultHeaders = response.headers;
            req.call = url.parse(options.host + options.path);
            req.call = url.format(req.call);

            // Response body
            req.result = body;

            if (config.debug) {
              console.log(util.inspect(body));
            }

            next();
        })
    }).on('error', function(e) {
        if (config.debug) {
            console.log('HEADERS: ' + JSON.stringify(res.headers));
            console.log("Got error: " + e.message);
            console.log("Error: " + util.inspect(e));
        };
    });

    if (requestBody) {
        apiCall.end(requestBody, 'utf-8');
    }
    else {
        apiCall.end();
    }
}


// Dynamic Helpers
// Passes variables to the view
app.dynamicHelpers({
    session: function(req, res) {
    // If api wasn't passed in as a parameter, check the path to see if it's there
        if (!req.params.api) {
            pathName = req.url.replace('/','');
            // Is it a valid API - if there's a config file we can assume so
            fs.stat(__dirname + '/public/data/' + pathName + '.json', function (error, stats) {
                if (stats) {
                    req.params.api = pathName;
                }
            });
        }       
        // If the cookie says we're authed for this particular API, set the session to authed as well
        if (req.params.api && req.session[req.params.api] && req.session[req.params.api]['authed']) {
            req.session['authed'] = true;
        }

        return req.session;
    },
    apiInfo: function(req, res) {
        if (req.params.api) {
            return apisConfig[req.params.api];
        } else {
            return apisConfig;
        }
    },
    apiName: function(req, res) {
        if (req.params.api) {
            return req.params.api;
        }
    },
    apiDefinition: function(req, res) {
        if (req.params.api) {
            var data = fs.readFileSync(__dirname + '/public/data/' + req.params.api + '.json');
            return JSON.parse(data);
        }
    }
})


//
// Routes
//
app.get('/', function(req, res) {
    res.render('listAPIs', {
        title: config.title
    });
});

// Process the API request
app.post('/processReq', processRequest, function(req, res) {
    var result = {
        headers: req.resultHeaders,
        response: req.result,
        call: req.call,
        code: req.res.statusCode
    };

    res.send(result);
});

app.post('/upload', function(req, res) {
  console.log(req.body.user);
  res.redirect('back');
});

// API shortname, all lowercase
app.get('/:api([^\.]+)', function(req, res) {
    req.params.api=req.params.api.replace(/\/$/,'');
    res.render('api');
});

// Only listen on $ node app.js

if (!module.parent) {
    var port = process.env.PORT || config.port;
    app.listen(port);
    console.log("Express server listening on port %d", app.address().port);
}
