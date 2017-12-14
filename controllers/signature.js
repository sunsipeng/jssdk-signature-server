
var request = require('request');
var eventproxy = require('eventproxy');
var ep = new eventproxy();
var uuid = require('uuid-js');
var crypto = require('crypto');    
var config = require('../common/config');

exports.jssdkSignature = function(req,res,next){
  ep.once('getJsapi_ticket_complete', function ($ticketdata) {
      var $data = typeof $ticketdata !== 'object' ? JSON.parse($ticketdata) : $ticketdata;

      var getSignature = function(){
          var uid = uuid.create(4).hex;
          var params = {
              noncestr:uid,
              jsapi_ticket:$data.ticket,
              timestamp:Date.now(),
              url: req.headers.referer
          }    
          
          var urlStr = `jsapi\_ticket=${params.jsapi_ticket}&noncestr=${params.noncestr}&timestamp=${params.timestamp}&url=${params.url}`;
          var sha1 = crypto.createHash('sha1');
              sha1.update(urlStr);
          var signature = sha1.digest('hex');
          console.log(JSON.stringify(params))
          
          global.$signature = {
              signature: signature,
              timestamp: params.timestamp,
              noncestr: params.noncestr,
              appid: config.appid,
              secret: config.secret
          }
          return res.send(global.$signature);
      }
      if(!global.$signature) {
          getSignature();
      } else {
          //token 失效重新签名
          if(Date.now() - global.$signature.timestamp > 7200e3){
              getSignature();
          } else {
              return res.send(global.$signature);
          }
      }
  });
  
  ep.once('get_access_token_complete', function (access_token) {
      const jsapiTicket = `https://api.weixin.qq.com/cgi-bin/ticket/getticket?access\_token=${access_token}&type=jsapi`;
      request(jsapiTicket, function (error, response, body) {
          if (!error && response.statusCode == 200) {
              return ep.emit('getJsapi_ticket_complete',body);
          }
      });
  });
  
  const accessTokenUrl = `https://api.weixin.qq.com/cgi-bin/token?appid=${config.appid}&secret=${config.secret}&grant_type=client_credential`;
  request(accessTokenUrl, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var $data = JSON.parse(body); 
      console.log('access_token=>' + $data.access_token);
      return ep.emit('get_access_token_complete',$data.access_token);
    }
  });
};
