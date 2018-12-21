'use strict';
module.exports = function(app) {
  var key = require('../controllers/todoListController');

  // setting the route for the controll
        // if we receive /keypair from py file, we post the pair and return
  app.route('/keypair')
        .post(key.post_pair);
        // receive '/private', we get the private key
  app.route('/private')
        .get(key.get_private);
        // We list them all in 'keys'
  app.route('/keys')
        .get(key.all);

};
