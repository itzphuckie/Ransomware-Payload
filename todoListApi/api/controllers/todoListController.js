'use strict';

var mongoose = require('mongoose'),
        Key = mongoose.model('Keys');

exports.all= function(req, res) {
  Key.find({}, function(err, key) {
    if (err)
      res.send(err);
    res.json(key);
  });
};

// Posting the key pair to server, the model will create a pair of private and public key
exports.post_pair = function(req, res) {
        // This is to check that it is not posing to the app key but somewhere else
        if(req.headers.appkey != 'xyzSecurity'){
                return res.status(500).send({success: false, message: 'That is not us !!!'});
        }
        Key.create({
                privatekey: req.body.privatekey,
                publickey: req.body.publickey
        },
        // This function to catch an error posting, otherwise return true
        function(err, key){
                if(err)
                        return res.status(500).send({success: false, error: err, message: 'Could not store the key pair due to Malware Errors'});
                res.status(200).send({success: true, message: 'Key pair are successfully stored.'});
        });

};
// GET the private key
exports.get_private = function(req, res){
        // Checking if it is getting from the app key, else return false
        if(req.headers.appkey != 'xyzSecurity'){
                 return res.status(500).send({success: false, message: 'That is not USSS !!!! '});
        }
        // Finding the public key from what we posted
        Key.findOne({
                publickey: req.headers.publickey
        },
        // This function to check for error, else get the private key
        function(err, key) {
                if(err)
                        res.send(err);
                if(!key){
                        return res.status(500).send({success: false, message: 'No private key found for that PUB PUB. Check Your Config.'});
                }
                else{
                         return res.status(200).send({success: true, privatekey: key.privatekey});
                }

        });
};
