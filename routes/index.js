var express = require('express');
var router = express.Router();
var signature = require('../controllers/signature');

router.get('/api/getsignature', signature.jssdkSignature);

module.exports = router;
