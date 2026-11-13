var express = require('express');
var app = express();

app.get('/a', function (req, res) {
    res.send(req.query.name); // njsscan-ignore: express_xss_fast
});

app.get('/b', function (req, res) {
    res.send(req.query.name); // njsscan-ignore: express_xss
});

app.get('/c', function (req, res) {
    res.send(req.query.name);
});
